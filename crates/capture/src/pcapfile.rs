//! Streaming pcap / pcapng file reader (gzip auto-detected). Not a hot path:
//! it allocates on open only; per-packet delivery borrows from the reader window.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};

use crate::{CaptureSource, Packet};

pub struct PcapFile {
    reader: Box<dyn PcapReaderIterator>,
    /// pcapng per-interface timestamp resolution → ns multiplier (index by if id).
    if_ts_mult: Vec<u64>,
    /// legacy pcap: 1000 for µs files, 1 for ns files
    legacy_mult: u64,
    pub packets: u64,
}

impl PcapFile {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let f = File::open(path)?;
        let rd: Box<dyn Read + Send> = if path.extension().is_some_and(|e| e == "gz") {
            Box::new(flate2::read::MultiGzDecoder::new(BufReader::with_capacity(1 << 20, f)))
        } else {
            Box::new(f)
        };
        Self::from_reader(rd)
    }

    pub fn from_reader(rd: Box<dyn Read + Send>) -> io::Result<Self> {
        let reader = create_reader(1 << 22, BufReader::with_capacity(1 << 20, rd))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pcap open: {e:?}")))?;
        Ok(Self { reader, if_ts_mult: Vec::new(), legacy_mult: 1000, packets: 0 })
    }
}

/// pcapng if_tsresol (option code 9): high bit clear ⇒ 10^-n seconds; set ⇒ 2^-n.
fn tsresol_to_ns_mult(opts: &[pcap_parser::PcapNGOption]) -> u64 {
    for o in opts {
        if o.code.0 == 9 {
            if let Some(&v) = o.value.first() {
                if v & 0x80 == 0 {
                    return 10u64.pow(9u32.saturating_sub(v as u32));
                }
                // 2^-n: approximate as ns via float — rare in practice
                return ((1e9f64) / (2f64.powi(v as i32 & 0x7f))) as u64;
            }
        }
    }
    1_000 // default resolution is microseconds
}

impl CaptureSource for PcapFile {
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<Option<usize>> {
        let mut n = 0;
        while n < max {
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(b) => {
                            let ts = b.ts_sec as u64 * 1_000_000_000 + b.ts_usec as u64 * self.legacy_mult;
                            sink(Packet { ts_ns: ts, data: b.data });
                            n += 1;
                        }
                        PcapBlockOwned::LegacyHeader(h) => {
                            self.legacy_mult = if h.is_nanosecond_precision() { 1 } else { 1000 };
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            self.if_ts_mult.push(tsresol_to_ns_mult(&idb.options));
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                            let mult = self.if_ts_mult.get(epb.if_id as usize).copied().unwrap_or(1000);
                            let raw = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                            let ts = raw * mult;
                            sink(Packet { ts_ns: ts, data: &epb.data[..epb.caplen as usize] });
                            n += 1;
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                            sink(Packet { ts_ns: 0, data: spb.data });
                            n += 1;
                        }
                        PcapBlockOwned::NG(_) => {}
                    }
                    self.reader.consume(offset);
                }
                Err(PcapError::Eof) => {
                    self.packets += n as u64;
                    return Ok(if n == 0 { None } else { Some(n) });
                }
                Err(PcapError::Incomplete(_)) => {
                    self.reader.refill().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pcap refill: {e:?}")))?;
                }
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("pcap: {e:?}"))),
            }
        }
        self.packets += n as u64;
        Ok(Some(n))
    }
}
