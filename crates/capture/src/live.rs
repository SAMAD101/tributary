//! Live capture via libpcap (feature `libpcap`). Works on macOS/Linux at low
//! rates; for correctness testing against a real multicast feed, not for 60M pps.

use std::io;

use pcap::{Active, Capture};

use crate::{CaptureSource, Packet};

pub struct LiveLibpcap {
    cap: Capture<Active>,
    pub packets: u64,
}

impl LiveLibpcap {
    /// `filter` is a BPF expression, e.g. `"udp and dst port 10378"`.
    pub fn open(device: &str, filter: Option<&str>, snaplen: i32) -> io::Result<Self> {
        let e = |e: pcap::Error| io::Error::other(e.to_string());
        let mut cap = Capture::from_device(device)
            .map_err(e)?
            .promisc(true)
            .snaplen(snaplen)
            .immediate_mode(true)
            .buffer_size(64 << 20)
            .timeout(1)
            .open()
            .map_err(e)?;
        if let Some(f) = filter {
            cap.filter(f, true).map_err(e)?;
        }
        Ok(Self { cap, packets: 0 })
    }
}

impl CaptureSource for LiveLibpcap {
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<Option<usize>> {
        let mut n = 0;
        while n < max {
            match self.cap.next_packet() {
                Ok(p) => {
                    let ts = p.header.ts.tv_sec as u64 * 1_000_000_000
                        + p.header.ts.tv_usec as u64 * 1000;
                    sink(Packet {
                        ts_ns: ts,
                        data: p.data,
                    });
                    n += 1;
                }
                Err(pcap::Error::TimeoutExpired) => break,
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        self.packets += n as u64;
        Ok(Some(n))
    }
}
