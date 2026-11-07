//! Packet sources behind one trait so the pipeline is backend-agnostic.
//!
//! * [`PcapFile`]  — pcap or pcapng, optionally gzip-compressed (dev, tests, replay)
//! * `LiveLibpcap` — feature `libpcap`; works on macOS at low rates
//! * `AfXdp`       — feature `afxdp`, Linux only; zero-copy UMEM, one socket per RSS queue
//!
//! Delivery is callback-based so every backend can hand out *borrowed* frame
//! bytes without copying (AF_XDP rx-ring descriptors, libpcap's buffer, or the
//! file reader's window).

use std::io;

pub mod pcapfile;
pub use pcapfile::PcapFile;

#[cfg(feature = "libpcap")]
pub mod live;
#[cfg(feature = "libpcap")]
pub use live::LiveLibpcap;

#[cfg(all(feature = "afxdp", target_os = "linux"))]
pub mod afxdp;
#[cfg(all(feature = "afxdp", target_os = "linux"))]
pub use afxdp::AfXdp;

/// One captured frame, borrowed from the backend for the duration of the callback.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    /// Capture timestamp, ns since Unix epoch (pcap ts / NIC hw ts / kernel ts).
    pub ts_ns: u64,
    /// L2 frame bytes (Ethernet header first).
    pub data: &'a [u8],
}

pub trait CaptureSource {
    /// Deliver up to `max` packets to `sink`.
    ///
    /// Returns `Ok(Some(n))` with the number delivered (0 = nothing available
    /// right now, spin/poll again), or `Ok(None)` when the source is exhausted
    /// (files). Live sources never return `None`.
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<Option<usize>>;

    /// Drain the whole source into `sink` in batches of `batch`. Convenience for files.
    fn for_each(&mut self, batch: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<u64> {
        let mut total = 0u64;
        while let Some(n) = self.poll(batch, sink)? {
            total += n as u64;
        }
        Ok(total)
    }
}

pub mod pcapwriter;
pub use pcapwriter::PcapWriter;
