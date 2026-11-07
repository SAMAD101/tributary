//! Minimal legacy-pcap writer (nanosecond magic). Used by absplit and tests.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub struct PcapWriter<W: Write> {
    w: W,
    pub packets: u64,
}

impl PcapWriter<BufWriter<File>> {
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(BufWriter::with_capacity(1 << 20, File::create(path)?))
    }
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W) -> io::Result<Self> {
        // magic (ns), version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        w.write_all(&0xA1B2_3C4Du32.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&65535u32.to_le_bytes())?;
        w.write_all(&1u32.to_le_bytes())?;
        Ok(Self { w, packets: 0 })
    }

    #[inline]
    pub fn write(&mut self, ts_ns: u64, data: &[u8]) -> io::Result<()> {
        self.w.write_all(&((ts_ns / 1_000_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&((ts_ns % 1_000_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(data)?;
        self.packets += 1;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.w.flush()?;
        Ok(self.w)
    }
}
