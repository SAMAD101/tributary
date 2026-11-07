//! Concurrent A/B runner: one reader thread per site pushes raw frames into a
//! lock-free SPSC ring; the arbiter thread pops from both, merging by capture
//! timestamp, and feeds [`Arbiter`].
//!
//! INFO: frames are memcpy'd once into fixed 1536-byte ring slots. On the
//! AF_XDP path you would pass UMEM frame indices instead and shard the arbiter
//! by RSS queue; the arbiter core itself is unchanged.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use capture::CaptureSource;
use rtrb::{Consumer, RingBuffer};
use tp_parse::{l2, Segment};

use crate::{Arbiter, Config, Emit, Report, Site};

pub const FRAME: usize = 1536;

#[derive(Clone, Copy)]
pub struct Frame {
    pub ts_ns: u64,
    /// When the reader thread enqueued this frame (for handoff latency).
    pub enq: Instant,
    pub len: u16,
    pub data: [u8; FRAME],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunStats {
    pub packets: [u64; 2],
    pub oversize_frames: [u64; 2],
    pub not_iex: [u64; 2],
    pub wall: Duration,
}

/// Spin-push into the ring; the producer never blocks in the kernel.
///
/// TODO(gap-producing experiment): add a no-backpressure mode that *drops* the
/// frame when the ring is full instead of spinning (count it per site), like a
/// NIC RX ring overflowing. Replaying above capacity then makes gapdetect/the
/// arbiter report the pipeline's own loss, and the input rate at which drops
/// start is the real capacity number of this software path. Today every gap
/// this project reports is injected (absplit / tests); replay never loses.
#[inline]
fn push_spin(p: &mut rtrb::Producer<Frame>, f: &Frame) {
    let mut f = *f;
    loop {
        match p.push(f) {
            Ok(()) => return,
            Err(rtrb::PushError::Full(back)) => {
                f = back;
                std::hint::spin_loop();
            }
        }
    }
}

fn reader<S: CaptureSource>(
    mut src: S,
    mut prod: rtrb::Producer<Frame>,
    done: Arc<AtomicBool>,
    stats: Arc<std::sync::Mutex<[u64; 2]>>,
) {
    let mut f = Frame {
        ts_ns: 0,
        enq: Instant::now(),
        len: 0,
        data: [0; FRAME],
    };
    let (mut n, mut oversize) = (0u64, 0u64);
    loop {
        let r = src.poll(64, &mut |pkt| {
            if pkt.data.len() > FRAME {
                oversize += 1;
                return;
            }
            f.ts_ns = pkt.ts_ns;
            f.len = pkt.data.len() as u16;
            f.data[..pkt.data.len()].copy_from_slice(pkt.data);
            f.enq = Instant::now();
            push_spin(&mut prod, &f);
            n += 1;
        });
        match r {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    *stats.lock().unwrap() = [n, oversize];
    done.store(true, Ordering::Release);
}

/// Run both sources through the arbiter concurrently until both are exhausted.
/// `max_wait` bounds how long the merger waits for the *other* ring to be
/// non-empty before proceeding one-sided (keeps a dead site from stalling us).
/// `on` receives each emission plus the enqueue time of the frame that
/// triggered it (ring handoff + arbitration latency = `enq.elapsed()`).
pub fn run_dual<SA, SB, F>(
    a: SA,
    b: SB,
    cfg: Config,
    ring: usize,
    max_wait: Duration,
    mut on: F,
) -> io::Result<(Report, RunStats)>
where
    SA: CaptureSource + Send + 'static,
    SB: CaptureSource + Send + 'static,
    F: FnMut(Emit<'_>, Instant),
{
    let t0 = Instant::now();
    let (pa, ca) = RingBuffer::<Frame>::new(ring);
    let (pb, cb) = RingBuffer::<Frame>::new(ring);
    let done = [
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ];
    let rs = [
        Arc::new(std::sync::Mutex::new([0u64; 2])),
        Arc::new(std::sync::Mutex::new([0u64; 2])),
    ];
    let ta = {
        let (d, s) = (done[0].clone(), rs[0].clone());
        std::thread::Builder::new()
            .name("site-a".into())
            .spawn(move || reader(a, pa, d, s))?
    };
    let tb = {
        let (d, s) = (done[1].clone(), rs[1].clone());
        std::thread::Builder::new()
            .name("site-b".into())
            .spawn(move || reader(b, pb, d, s))?
    };

    let mut arb = Arbiter::new(cfg);
    let mut cons = [ca, cb];
    let mut finished = [false, false];
    let mut stats = RunStats::default();

    // Merge loop: pick the ring whose head has the smaller timestamp.
    let mut waited_since: Option<Instant> = None;
    loop {
        let head = |c: &Consumer<Frame>| c.peek().ok().map(|f| f.ts_ns);
        let (ha, hb) = (head(&cons[0]), head(&cons[1]));
        let da = finished[0] || done[0].load(Ordering::Acquire) && cons[0].is_empty();
        let db = finished[1] || done[1].load(Ordering::Acquire) && cons[1].is_empty();
        let pick = match (ha, hb) {
            (Some(x), Some(y)) => Some(if x <= y { 0 } else { 1 }),
            (Some(_), None) if db || waited_since.is_some_and(|t| t.elapsed() > max_wait) => {
                Some(0)
            }
            (None, Some(_)) if da || waited_since.is_some_and(|t| t.elapsed() > max_wait) => {
                Some(1)
            }
            (None, None) if da && db => break,
            _ => None,
        };
        let Some(i) = pick else {
            waited_since.get_or_insert_with(Instant::now);
            std::hint::spin_loop();
            continue;
        };
        waited_since = None;
        // Process the frame in place in the ring slot (no 1.5 KB copy-out), then release it.
        let chunk = cons[i].read_chunk(1).unwrap();
        let f: &Frame = &chunk.as_slices().0[0];
        let site = if i == 0 { Site::A } else { Site::B };
        stats.packets[i] += 1;
        let enq = f.enq;
        let mut sink = |e: Emit<'_>| on(e, enq);
        match l2::udp_payload_fast(&f.data[..f.len as usize]).and_then(|u| Segment::parse(u).ok()) {
            Some(seg) => arb.push(site, &seg, f.ts_ns, &mut sink),
            None => stats.not_iex[i] += 1,
        }
        chunk.commit_all();
        // Site finished and drained → tell the arbiter so it stops waiting on it.
        for j in 0..2 {
            if !finished[j] && done[j].load(Ordering::Acquire) && cons[j].is_empty() {
                finished[j] = true;
                arb.eof(if j == 0 { Site::A } else { Site::B }, &mut sink);
            }
        }
    }
    let now = Instant::now();
    arb.finish(&mut |e| on(e, now));
    ta.join().ok();
    tb.join().ok();
    for (j, r) in rs.iter().enumerate() {
        stats.oversize_frames[j] = r.lock().unwrap()[1];
    }
    stats.wall = t0.elapsed();
    Ok((arb.report(), stats))
}
