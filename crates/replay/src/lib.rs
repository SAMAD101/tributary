//! Load a pcap into memory once, then replay it through the pipeline at a
//! controlled rate (or flat out) — from one or many cores — so throughput can
//! be measured *above* what one wire delivers.
//!
//! Pacing spins on `Instant` (no `sleep`, no syscalls in the loop) so the
//! achieved rate tracks the target closely down to sub-microsecond gaps.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use capture::{CaptureSource, Packet, PcapFile};
use gapdetect::GapDetector;
use metrics::{Counters, Latency, LatencySummary, Rates};
use serde::Serialize;
use tp_parse::{l2, msg, Segment};

/// A pcap fully resident in memory: frames packed back-to-back + an index.
pub struct Loaded {
    buf: Vec<u8>,
    idx: Vec<Entry>,
    pub messages: u64,
    pub bytes: u64,
    /// Lowest first_seq / highest next_seq seen (for per-pass sequence rewriting).
    pub seq_lo: u64,
    pub seq_hi: u64,
}

#[derive(Clone, Copy)]
struct Entry { off: u32, len: u32, ts: u64 }

impl Loaded {
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut src = PcapFile::open(path)?;
        let mut l = Self::empty();
        src.for_each(64, &mut |p| l.push(p.ts_ns, p.data))?;
        Ok(l)
    }

    /// Build from raw frames (used by absplit-in-memory and tests).
    pub fn from_frames<'a>(frames: impl IntoIterator<Item = (u64, &'a [u8])>) -> Self {
        let mut l = Self::empty();
        for (ts, data) in frames { l.push(ts, data); }
        l
    }

    /// Empty set; fill with [`Loaded::push`].
    pub fn empty() -> Self {
        Self { buf: Vec::new(), idx: Vec::new(), messages: 0, bytes: 0, seq_lo: u64::MAX, seq_hi: 0 }
    }

    /// Append one frame.
    pub fn push(&mut self, ts: u64, data: &[u8]) {
        self.idx.push(Entry { off: self.buf.len() as u32, len: data.len() as u32, ts });
        self.buf.extend_from_slice(data);
        self.bytes = self.buf.len() as u64;
        if let Some(seg) = l2::udp_payload_fast(data).and_then(|u| Segment::parse(u).ok()) {
            self.messages += seg.header.message_count as u64;
            self.seq_lo = self.seq_lo.min(seg.header.first_seq);
            self.seq_hi = self.seq_hi.max(seg.header.next_seq());
        }
    }

    /// Number of sequence numbers the file spans (next pass starts here).
    pub fn seq_span(&self) -> u64 { self.seq_hi.saturating_sub(self.seq_lo) }

    pub fn packets(&self) -> usize { self.idx.len() }
    #[inline]
    pub fn get(&self, i: usize) -> Packet<'_> {
        let e = self.idx[i];
        Packet { ts_ns: e.ts, data: &self.buf[e.off as usize..(e.off + e.len) as usize] }
    }
    pub fn iter(&self) -> impl Iterator<Item = Packet<'_>> { (0..self.idx.len()).map(|i| self.get(i)) }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rate {
    /// As fast as the consumer can take it.
    Max,
    /// Target packets per second.
    Pps(f64),
}

impl std::str::FromStr for Rate {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("max") { return Ok(Rate::Max); }
        let (num, mult) = match s.to_ascii_lowercase() {
            x if x.ends_with('m') => (x[..x.len() - 1].to_string(), 1e6),
            x if x.ends_with('k') => (x[..x.len() - 1].to_string(), 1e3),
            x => (x, 1.0),
        };
        num.parse::<f64>().map(|v| Rate::Pps(v * mult)).map_err(|e| e.to_string())
    }
}

/// Spin-based pacer: `wait(n)` blocks until packet number `n` is due.
pub struct Pacer { start: Instant, ns_per_pkt: f64 }
impl Pacer {
    pub fn new(rate: Rate) -> Self {
        Self { start: Instant::now(), ns_per_pkt: match rate { Rate::Max => 0.0, Rate::Pps(p) => 1e9 / p } }
    }
    #[inline]
    pub fn wait(&self, sent: u64) {
        if self.ns_per_pkt == 0.0 { return; }
        let due = self.start + Duration::from_nanos((sent as f64 * self.ns_per_pkt) as u64);
        while Instant::now() < due { std::hint::spin_loop(); }
    }
}

/// A `CaptureSource` over an in-memory pcap, replayed `repeat` times at `rate`.
/// Each pass shifts capture timestamps by the file's time span and (by
/// default) rewrites IEX-TP `first_seq` by the file's sequence span, so N
/// passes look like one long contiguous session instead of N duplicates.
pub struct MemSource {
    data: Arc<Loaded>,
    /// Pass-local copy of the frames with sequence numbers rewritten (pass ≥ 1).
    scratch: Vec<u8>,
    /// Absolute offsets of each IEX-TP `first_seq` field in `scratch`.
    seq_offs: Vec<u32>,
    rewrite_seq: bool,
    pos: usize,
    round: usize,
    repeat: usize,
    span: u64,
    pacer: Pacer,
    sent: u64,
}

impl MemSource {
    pub fn new(data: Arc<Loaded>, rate: Rate, repeat: usize) -> Self {
        let span = if data.packets() > 1 { data.get(data.packets() - 1).ts_ns - data.get(0).ts_ns + 1 } else { 1 };
        Self { data, scratch: Vec::new(), seq_offs: Vec::new(), rewrite_seq: true, pos: 0, round: 0, repeat: repeat.max(1), span, pacer: Pacer::new(rate), sent: 0 }
    }

    /// Keep original sequence numbers on every pass (passes ≥ 1 then look like duplicates).
    pub fn keep_sequences(mut self) -> Self { self.rewrite_seq = false; self }

    /// Prepare the scratch copy for pass `round` (control plane, once per pass).
    /// First call clones the buffer and records where every IEX-TP `first_seq`
    /// lives; later passes just add the sequence span in place (≈1 ns/packet).
    fn prepare_pass(&mut self, round: usize) {
        if !self.rewrite_seq || round == 0 { return; }
        if self.scratch.is_empty() {
            self.scratch = self.data.buf.clone();
            self.seq_offs = self.data.idx.iter().filter_map(|e| {
                let (a, b) = (e.off as usize, (e.off + e.len) as usize);
                let frame = &self.data.buf[a..b];
                let udp = l2::udp_payload_fast(frame)?;
                Segment::parse(udp).ok()?;
                // IEX-TP first_seq is at UDP-payload offset 24.
                Some((a + (udp.as_ptr() as usize - frame.as_ptr() as usize) + 24) as u32)
            }).collect();
        }
        let span = self.data.seq_span();
        for &o in &self.seq_offs {
            let o = o as usize;
            let v = u64::from_le_bytes(self.scratch[o..o + 8].try_into().unwrap());
            self.scratch[o..o + 8].copy_from_slice(&(v + span).to_le_bytes());
        }
    }
}

impl CaptureSource for MemSource {
    #[inline]
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<Option<usize>> {
        if self.round >= self.repeat { return Ok(None); }
        if self.pos == 0 { self.prepare_pass(self.round); }
        let n = max.min(self.data.packets() - self.pos);
        let off = self.round as u64 * self.span;
        let buf: &[u8] = if self.rewrite_seq && self.round > 0 { &self.scratch } else { &self.data.buf };
        for (k, e) in self.data.idx[self.pos..self.pos + n].iter().enumerate() {
            self.pacer.wait(self.sent + k as u64 + 1); // per-packet pacing: no bursts
            sink(Packet { ts_ns: e.ts + off, data: &buf[e.off as usize..(e.off + e.len) as usize] });
        }
        self.pos += n;
        self.sent += n as u64;
        if self.pos >= self.data.packets() { self.pos = 0; self.round += 1; }
        Ok(Some(n))
    }
}

/// Result of one worker core running parse → decode → gapdetect over the data.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerResult {
    pub core: Option<usize>,
    pub counters: Counters,
    pub rates: Rates,
    /// Per-batch processing time ÷ batch size, i.e. per-packet cost (ns).
    pub per_packet: LatencySummary,
    pub gaps: u64,
    pub dups: u64,
    pub decode_errors: u64,
}

/// The per-core hot loop: L2→UDP→IEX-TP→messages→gap detection, in batches.
/// `decode` also fully decodes every message (the realistic feed-handler cost).
pub fn parse_worker(data: Arc<Loaded>, rate: Rate, repeat: usize, batch: usize, decode: bool) -> WorkerResult {
    let mut src = MemSource::new(data, rate, repeat);
    let mut det = GapDetector::new();
    let mut c = Counters::default();
    let mut lat = Latency::new();
    let (mut sink_acc, mut decode_errors) = (0u64, 0u64);
    let t0 = Instant::now();
    loop {
        let tb = Instant::now();
        let mut n_pk = 0u64;
        let r = src.poll(batch, &mut |p| {
            n_pk += 1;
            c.bytes += p.data.len() as u64;
            let Some(seg) = l2::udp_payload_fast(p.data).and_then(|u| Segment::parse(u).ok()) else { return };
            det.observe(&seg.header, p.ts_ns);
            c.messages += seg.header.message_count as u64;
            if decode {
                for m in seg.messages() {
                    match m.map(|(_, b)| msg::decode(b)) {
                        Ok(Ok(m)) => sink_acc = sink_acc.wrapping_add(m.timestamp() as u64 ^ m.kind() as u64),
                        _ => decode_errors += 1,
                    }
                }
            } else {
                for (_, b) in seg.messages().flatten() {
                    sink_acc = sink_acc.wrapping_add(msg::peek_kind_ts(b).map(|(k, t)| k as u64 ^ t as u64).unwrap_or(0));
                }
            }
        });
        if n_pk > 0 {
            c.packets += n_pk;
            lat.record_ns(tb.elapsed().as_nanos() as u64 / n_pk);
        }
        match r { Ok(Some(_)) => {}, _ => break }
    }
    let el = t0.elapsed();
    std::hint::black_box(sink_acc);
    WorkerResult { core: None, counters: c, rates: c.rates(el), per_packet: lat.summary(), gaps: det.total_missing(), dups: det.sessions().map(|s| s.duplicate_msgs).sum(), decode_errors }
}

/// Run `cores` independent parse workers in parallel (each pinned to its own
/// core when possible) over the same data. Returns per-core results.
pub fn parse_workers(data: Arc<Loaded>, cores: usize, rate: Rate, repeat: usize, batch: usize, decode: bool) -> Vec<WorkerResult> {
    let ids = core_affinity::get_core_ids().unwrap_or_default();
    let handles: Vec<_> = (0..cores).map(|i| {
        let data = data.clone();
        let id = ids.get(i % ids.len().max(1)).copied();
        std::thread::spawn(move || {
            let pinned = id.map(core_affinity::set_for_current).unwrap_or(false);
            let mut r = parse_worker(data, rate, repeat, batch, decode);
            r.core = if pinned { id.map(|c| c.id) } else { None };
            r
        })
    }).collect();
    handles.into_iter().map(|h| h.join().expect("worker panicked")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/deep_20191224_1430.pcap.gz");

    #[test]
    fn rate_parse() {
        assert_eq!("max".parse::<Rate>().unwrap(), Rate::Max);
        assert_eq!("2.5m".parse::<Rate>().unwrap(), Rate::Pps(2_500_000.0));
        assert_eq!("100k".parse::<Rate>().unwrap(), Rate::Pps(100_000.0));
        assert_eq!("42".parse::<Rate>().unwrap(), Rate::Pps(42.0));
    }

    #[test]
    fn mem_source_repeats_and_paces() {
        let d = Arc::new(Loaded::load(FIXTURE).unwrap());
        assert_eq!(d.packets(), 2000);
        assert_eq!(d.messages, 10520);
        let mut s = MemSource::new(d.clone(), Rate::Pps(200_000.0), 2);
        let mut n = 0u64;
        let mut last_ts = 0;
        let t0 = Instant::now();
        while let Some(k) = s.poll(64, &mut |p| { assert!(p.ts_ns >= last_ts); last_ts = p.ts_ns; }).unwrap() { n += k as u64; }
        let el = t0.elapsed().as_secs_f64();
        assert_eq!(n, 4000);
        assert!(el >= 0.02 - 0.002, "4000 pkts at 200k pps must take ≥ 20ms, took {el:.4}s");
    }

    #[test]
    fn worker_counts_everything() {
        let d = Arc::new(Loaded::load(FIXTURE).unwrap());
        let r = parse_worker(d, Rate::Max, 3, 64, true);
        assert_eq!(r.counters.packets, 6000);
        assert_eq!(r.counters.messages, 10520 * 3);
        assert_eq!(r.decode_errors, 0);
        assert!(r.rates.pps > 0.0);
        // passes are stitched into one contiguous sequence space: no gaps, no dups
        assert_eq!(r.gaps, 0);
        assert_eq!(r.dups, 0);
    }

    #[test]
    fn passes_are_contiguous_in_sequence() {
        let d = Arc::new(Loaded::load(FIXTURE).unwrap());
        let mut s = MemSource::new(d.clone(), Rate::Max, 3);
        let mut det = GapDetector::new();
        let mut last = None;
        while s.poll(64, &mut |p| {
            let seg = Segment::parse(l2::udp_payload_fast(p.data).unwrap()).unwrap();
            det.observe(&seg.header, p.ts_ns);
            last = Some(seg.header.next_seq());
        }).unwrap().is_some() {}
        let r = &det.report()[0];
        assert_eq!((r.gap_count, r.duplicate_segments, r.messages), (0, 0, 10520 * 3));
        assert_eq!(last, Some(d.seq_lo + 3 * d.seq_span()));
        // keep_sequences → passes 2,3 are pure duplicates
        let mut s = MemSource::new(d.clone(), Rate::Max, 3).keep_sequences();
        let mut det = GapDetector::new();
        while s.poll(64, &mut |p| { det.observe(&Segment::parse(l2::udp_payload_fast(p.data).unwrap()).unwrap().header, p.ts_ns); }).unwrap().is_some() {}
        assert_eq!(det.report()[0].duplicate_msgs, 10520 * 2);
    }
}
