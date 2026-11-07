//! AF_XDP capture backend (Linux only, feature `afxdp`).
//!
//! Library choice: **xsk-rs** (0.9, actively maintained, wraps libxdp/libbpf
//! via `libxdp-sys`). libbpf-rs would need us to hand-roll the XSK ring
//! handling; xsk-rs gives us `Umem` / `FillQueue` / `RxQueue` directly and
//! loads libxdp's default `xsk_def_xdp_prog` (a redirect-to-XSKMAP program)
//! on the interface for us.
//!
//! Design (one instance per RSS queue, on its own pinned thread):
//! * One UMEM per queue (NUMA-local, optionally huge-page backed), all frames
//!   posted to the fill ring up front.
//! * `poll` consumes up to `max` descriptors from the RX ring — a pure
//!   userspace ring read, no syscall — hands the frame bytes to the sink
//!   **borrowed straight out of the UMEM** (zero copy), then returns the
//!   frames to the fill ring.
//! * With `XDP_USE_NEED_WAKEUP` the only syscall is an occasional
//!   `poll()`/`sendto()` wakeup when the driver has gone to sleep.
//! * Timestamps: this backend stamps `CLOCK_REALTIME` once per batch (vDSO,
//!   no kernel entry). Per-packet NIC hardware timestamps need a custom XDP
//!   program using `bpf_xdp_metadata_rx_timestamp` (kernel ≥ 6.3, driver
//!   support) writing into the frame headroom — see docs/AFXDP.md.
//!
//! See docs/AFXDP.md for hugepages, RSS/queue setup, IRQ affinity, isolcpus.

use std::ffi::CString;
use std::io;
use std::num::NonZeroU32;

use xsk_rs::config::{BindFlags, FrameSize, Interface, QueueSize, SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use crate::{CaptureSource, Packet};

#[derive(Debug, Clone)]
pub struct AfXdpConfig {
    pub ifname: String,
    /// RSS queue to bind to. Run one `AfXdp` per queue.
    pub queue_id: u32,
    /// UMEM frames (power of two). 4096 × 2 KiB = 8 MiB per queue.
    pub frame_count: u32,
    /// 2048 or 4096.
    pub frame_size: u32,
    pub huge_pages: bool,
    /// Require driver zero-copy (fail instead of silently falling back to copy mode).
    pub zero_copy: bool,
    /// Pin the calling thread to this core before touching the rings.
    pub pin_core: Option<usize>,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self { ifname: "eth0".into(), queue_id: 0, frame_count: 4096, frame_size: 2048, huge_pages: true, zero_copy: true, pin_core: None }
    }
}

pub struct AfXdp {
    umem: Umem,
    rx: RxQueue,
    fq: FillQueue,
    _tx: TxQueue,
    _cq: CompQueue,
    /// Scratch descriptors for one RX batch.
    batch: Vec<FrameDesc>,
    pub packets: u64,
    pub wakeups: u64,
}

fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl AfXdp {
    pub fn open(cfg: &AfXdpConfig) -> io::Result<Self> {
        if let Some(core) = cfg.pin_core {
            // core_affinity is a dev-dep of the pipeline; keep this crate light and use sched_setaffinity directly.
            unsafe {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(core, &mut set);
                if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        let frames = NonZeroU32::new(cfg.frame_count).ok_or_else(|| err("frame_count must be > 0"))?;
        let umem_cfg = UmemConfig::builder()
            .frame_size(FrameSize::new(cfg.frame_size).map_err(err)?)
            .fill_queue_size(QueueSize::new(cfg.frame_count).map_err(err)?)
            .comp_queue_size(QueueSize::new(cfg.frame_count).map_err(err)?)
            .build()
            .map_err(err)?;
        let (umem, descs) = Umem::new(umem_cfg, frames, cfg.huge_pages).map_err(err)?;

        let mut bind = BindFlags::XDP_USE_NEED_WAKEUP;
        if cfg.zero_copy { bind |= BindFlags::XDP_ZEROCOPY; }
        let sock_cfg = SocketConfig::builder()
            .rx_queue_size(QueueSize::new(cfg.frame_count / 2).map_err(err)?)
            .tx_queue_size(QueueSize::new(64).map_err(err)?)
            .bind_flags(bind)
            .build();
        let iface = Interface::new(CString::new(cfg.ifname.as_str()).map_err(err)?);
        // SAFETY: fresh UMEM, first socket bound to (ifname, queue): the
        // shared-UMEM prog-load caveat in xsk-rs does not apply.
        let (tx, rx, fq_cq) = unsafe { Socket::new(sock_cfg, &umem, &iface, cfg.queue_id) }.map_err(err)?;
        let (mut fq, cq) = fq_cq.ok_or_else(|| err("socket did not return fill/comp queues"))?;

        // Post every frame to the fill ring: the kernel now owns them until they show up on RX.
        // SAFETY: descs are this UMEM's, none are in use.
        let posted = unsafe { fq.produce(&descs) };
        if posted != descs.len() {
            return Err(err(format!("only {posted}/{} frames posted to fill ring", descs.len())));
        }
        let batch = vec![descs[0]; cfg.frame_count as usize / 2];
        Ok(Self { umem, rx, fq, _tx: tx, _cq: cq, batch, packets: 0, wakeups: 0 })
    }

    #[inline]
    fn now_ns() -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // vDSO fast path on Linux; not a real syscall.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
}

impl CaptureSource for AfXdp {
    #[inline]
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<Option<usize>> {
        let want = max.min(self.batch.len());
        // SAFETY: descriptors are scratch; consume overwrites them with frames the kernel just handed us.
        let n = unsafe { self.rx.consume(&mut self.batch[..want]) };
        if n == 0 {
            if self.fq.needs_wakeup() {
                self.wakeups += 1;
                self.fq.wakeup(self.rx.fd_mut(), 0)?;
            }
            return Ok(Some(0));
        }
        let ts = Self::now_ns();
        for d in &self.batch[..n] {
            // SAFETY: `d` was just consumed from RX, so we own the frame until we re-post it below.
            let data = unsafe { self.umem.data(d) };
            sink(Packet { ts_ns: ts, data: data.contents() });
        }
        // Give the frames back to the kernel.
        // SAFETY: we are done reading them; fill ring has capacity == frame_count.
        let back = unsafe { self.fq.produce(&self.batch[..n]) };
        debug_assert_eq!(back, n);
        self.packets += n as u64;
        Ok(Some(n))
    }
}
