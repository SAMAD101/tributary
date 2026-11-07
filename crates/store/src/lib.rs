//! `.tri` files: the merged, gap-free-where-possible stream, block-compressed
//! with zstd and indexed so a `(session, seq)` or capture-time range can be
//! read without scanning the file.
//!
//! ```text
//! file  := header | block* | index_json | u64 index_off | u64 index_len | magic
//! header:= magic "TRI1" | u32 block_msgs
//! block := zstd( record* )                       (one session per block)
//! record:= uvarint Δseq | svarint Δcapture_ns | svarint Δsend_ns | u8 site | uvarint len | body
//! index := JSON { blocks: [{session, first_seq, last_seq, count, first_ns, last_ns, off, clen, rlen}], gaps: [...] }
//! ```
//! Deltas start from 0 at the top of every block, so blocks are independently
//! decodable. Sequences inside a block are ascending; blocks are appended in
//! emission order, so per-session block ranges are ascending too and a range
//! query is a binary search on the index followed by decompressing only the
//! blocks that overlap.
//!
//! Sized for the problem, not the sample: see [`RETENTION.md`](../RETENTION.md)
//! for the 5 TB/day discussion (partitioning, compression, retention).

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use gapdetect::GapRange;
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 4] = b"TRI1";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a .tri file")]
    Magic,
    #[error("corrupt index: {0}")]
    Index(String),
    #[error("corrupt block: {0}")]
    Block(&'static str),
}

/// One stored message (borrowed body when reading).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    pub session_id: u32,
    pub seq: u64,
    pub capture_ns: u64,
    pub send_ns: i64,
    pub site: u8,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockMeta {
    pub session: u32,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u32,
    pub first_ns: u64,
    pub last_ns: u64,
    pub off: u64,
    pub clen: u32,
    pub rlen: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub blocks: Vec<BlockMeta>,
    /// Residual gaps the arbiter reported (session, range) — a reader can tell
    /// "missing at the source" from "bug in the store".
    pub gaps: Vec<(u32, GapRange)>,
    pub messages: u64,
    pub raw_bytes: u64,
    pub compressed_bytes: u64,
}

// ---- varints -----------------------------------------------------------------

#[inline]
fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 { out.push((v as u8) | 0x80); v >>= 7; }
    out.push(v as u8);
}
#[inline]
fn put_svarint(out: &mut Vec<u8>, v: i64) { put_uvarint(out, ((v << 1) ^ (v >> 63)) as u64) }
#[inline]
fn get_uvarint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let (mut v, mut shift) = (0u64, 0);
    loop {
        let &x = b.get(*pos)?;
        *pos += 1;
        v |= ((x & 0x7f) as u64) << shift;
        if x & 0x80 == 0 { return Some(v); }
        shift += 7;
        if shift > 63 { return None; }
    }
}
#[inline]
fn get_svarint(b: &[u8], pos: &mut usize) -> Option<i64> {
    let u = get_uvarint(b, pos)?;
    Some(((u >> 1) as i64) ^ -((u & 1) as i64))
}

// ---- writer -------------------------------------------------------------------

pub struct Writer<W: Write + Seek> {
    w: W,
    block_msgs: usize,
    level: i32,
    cur: Vec<u8>,
    cur_meta: Option<BlockMeta>,
    prev: (u64, u64, i64),
    index: Index,
    off: u64,
}

impl Writer<BufWriter<File>> {
    pub fn create(path: impl AsRef<Path>, block_msgs: usize, level: i32) -> Result<Self, StoreError> {
        Self::new(BufWriter::with_capacity(1 << 20, File::create(path)?), block_msgs, level)
    }
}

impl<W: Write + Seek> Writer<W> {
    pub fn new(mut w: W, block_msgs: usize, level: i32) -> Result<Self, StoreError> {
        w.write_all(MAGIC)?;
        w.write_all(&(block_msgs as u32).to_le_bytes())?;
        Ok(Self { w, block_msgs, level, cur: Vec::with_capacity(block_msgs * 48), cur_meta: None, prev: (0, 0, 0), index: Index::default(), off: 8 })
    }

    /// Append one message. Messages must arrive in per-session sequence order.
    #[inline]
    pub fn push(&mut self, r: &Record<'_>) -> Result<(), StoreError> {
        match &self.cur_meta {
            Some(m) if m.session != r.session_id || m.count as usize >= self.block_msgs => self.flush_block()?,
            _ => {}
        }
        let m = self.cur_meta.get_or_insert(BlockMeta { session: r.session_id, first_seq: r.seq, last_seq: r.seq, count: 0, first_ns: r.capture_ns, last_ns: r.capture_ns, off: 0, clen: 0, rlen: 0 });
        if m.count == 0 { self.prev = (0, 0, 0); }
        put_uvarint(&mut self.cur, r.seq.wrapping_sub(self.prev.0));
        put_svarint(&mut self.cur, r.capture_ns as i64 - self.prev.1 as i64);
        put_svarint(&mut self.cur, r.send_ns - self.prev.2);
        self.cur.push(r.site);
        put_uvarint(&mut self.cur, r.body.len() as u64);
        self.cur.extend_from_slice(r.body);
        self.prev = (r.seq, r.capture_ns, r.send_ns);
        m.last_seq = r.seq;
        m.first_ns = m.first_ns.min(r.capture_ns);
        m.last_ns = m.last_ns.max(r.capture_ns);
        m.count += 1;
        Ok(())
    }

    pub fn push_gap(&mut self, session: u32, from: u64, to: u64) {
        self.index.gaps.push((session, GapRange { from, to }));
    }

    fn flush_block(&mut self) -> Result<(), StoreError> {
        let Some(mut m) = self.cur_meta.take() else { return Ok(()) };
        let comp = zstd::bulk::compress(&self.cur, self.level)?;
        m.off = self.off;
        m.rlen = self.cur.len() as u32;
        m.clen = comp.len() as u32;
        self.w.write_all(&comp)?;
        self.off += comp.len() as u64;
        self.index.messages += m.count as u64;
        self.index.raw_bytes += m.rlen as u64;
        self.index.compressed_bytes += m.clen as u64;
        self.index.blocks.push(m);
        self.cur.clear();
        Ok(())
    }

    /// Write the index + footer. Returns the index (with totals).
    pub fn finish(mut self) -> Result<Index, StoreError> {
        self.flush_block()?;
        let idx = serde_json::to_vec(&self.index).map_err(|e| StoreError::Index(e.to_string()))?;
        self.w.write_all(&idx)?;
        self.w.write_all(&self.off.to_le_bytes())?;
        self.w.write_all(&(idx.len() as u64).to_le_bytes())?;
        self.w.write_all(MAGIC)?;
        self.w.flush()?;
        Ok(self.index)
    }
}

// ---- reader -------------------------------------------------------------------

pub struct Store {
    f: BufReader<File>,
    pub index: Index,
    pub block_msgs: u32,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let mut f = BufReader::new(File::open(path)?);
        let mut hdr = [0u8; 8];
        f.read_exact(&mut hdr)?;
        if &hdr[..4] != MAGIC { return Err(StoreError::Magic); }
        let block_msgs = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        f.seek(SeekFrom::End(-20))?;
        let mut foot = [0u8; 20];
        f.read_exact(&mut foot)?;
        if &foot[16..] != MAGIC { return Err(StoreError::Magic); }
        let off = u64::from_le_bytes(foot[..8].try_into().unwrap());
        let len = u64::from_le_bytes(foot[8..16].try_into().unwrap());
        f.seek(SeekFrom::Start(off))?;
        let mut idx = vec![0u8; len as usize];
        f.read_exact(&mut idx)?;
        let index: Index = serde_json::from_slice(&idx).map_err(|e| StoreError::Index(e.to_string()))?;
        Ok(Self { f, index, block_msgs })
    }

    /// Decompress one block into `buf`.
    pub fn read_block(&mut self, m: &BlockMeta, buf: &mut Vec<u8>) -> Result<(), StoreError> {
        self.f.seek(SeekFrom::Start(m.off))?;
        let mut comp = vec![0u8; m.clen as usize];
        self.f.read_exact(&mut comp)?;
        buf.clear();
        buf.reserve(m.rlen as usize);
        *buf = zstd::bulk::decompress(&comp, m.rlen as usize)?;
        Ok(())
    }

    /// Blocks of `session` overlapping `[seq_lo, seq_hi]` (binary search — per-session block ranges are ascending).
    pub fn blocks_for_seq(&self, session: u32, seq_lo: u64, seq_hi: u64) -> Vec<BlockMeta> {
        let bs: Vec<&BlockMeta> = self.index.blocks.iter().filter(|b| b.session == session).collect();
        let start = bs.partition_point(|b| b.last_seq < seq_lo);
        bs[start..].iter().take_while(|b| b.first_seq <= seq_hi).map(|b| (*b).clone()).collect()
    }

    /// Blocks overlapping capture-time `[ns_lo, ns_hi]` (any session; block time ranges are ascending in append order).
    pub fn blocks_for_time(&self, ns_lo: u64, ns_hi: u64) -> Vec<BlockMeta> {
        let bs = &self.index.blocks;
        let start = bs.partition_point(|b| b.last_ns < ns_lo);
        bs[start..].iter().take_while(|b| b.first_ns <= ns_hi).cloned().collect()
    }

    /// Read every record of `session` with `seq_lo <= seq <= seq_hi`, in order.
    pub fn read_seq_range(&mut self, session: u32, seq_lo: u64, seq_hi: u64, mut f: impl FnMut(Record<'_>)) -> Result<u64, StoreError> {
        let mut n = 0;
        let mut buf = Vec::new();
        for m in self.blocks_for_seq(session, seq_lo, seq_hi) {
            self.read_block(&m, &mut buf)?;
            for_each_record(&buf, m.session, |r| { if r.seq >= seq_lo && r.seq <= seq_hi { n += 1; f(r) } })?;
        }
        Ok(n)
    }

    /// Read every record with `ns_lo <= capture_ns <= ns_hi`.
    pub fn read_time_range(&mut self, ns_lo: u64, ns_hi: u64, mut f: impl FnMut(Record<'_>)) -> Result<u64, StoreError> {
        let mut n = 0;
        let mut buf = Vec::new();
        for m in self.blocks_for_time(ns_lo, ns_hi) {
            self.read_block(&m, &mut buf)?;
            for_each_record(&buf, m.session, |r| { if r.capture_ns >= ns_lo && r.capture_ns <= ns_hi { n += 1; f(r) } })?;
        }
        Ok(n)
    }

    pub fn compression_ratio(&self) -> f64 {
        self.index.raw_bytes as f64 / self.index.compressed_bytes.max(1) as f64
    }
}

/// Walk the records of a decompressed block.
pub fn for_each_record(buf: &[u8], session: u32, mut f: impl FnMut(Record<'_>)) -> Result<(), StoreError> {
    let (mut pos, mut seq, mut cap, mut send) = (0usize, 0u64, 0u64, 0i64);
    while pos < buf.len() {
        let e = || StoreError::Block("truncated record");
        seq = seq.wrapping_add(get_uvarint(buf, &mut pos).ok_or_else(e)?);
        cap = (cap as i64 + get_svarint(buf, &mut pos).ok_or_else(e)?) as u64;
        send += get_svarint(buf, &mut pos).ok_or_else(e)?;
        let site = *buf.get(pos).ok_or_else(e)?;
        pos += 1;
        let len = get_uvarint(buf, &mut pos).ok_or_else(e)? as usize;
        let body = buf.get(pos..pos + len).ok_or_else(e)?;
        pos += len;
        f(Record { session_id: session, seq, capture_ns: cap, send_ns: send, site, body });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, body: &[u8]) -> Record<'_> {
        Record { session_id: 7, seq, capture_ns: 1_000_000 + seq * 1000, send_ns: 900_000 + seq as i64 * 1000, site: (seq % 2) as u8, body }
    }

    #[test]
    fn varints_roundtrip() {
        let mut b = Vec::new();
        for v in [0u64, 1, 127, 128, 300, u64::MAX] { put_uvarint(&mut b, v); }
        for v in [0i64, -1, 1, -64, 64, i64::MIN, i64::MAX] { put_svarint(&mut b, v); }
        let mut p = 0;
        for v in [0u64, 1, 127, 128, 300, u64::MAX] { assert_eq!(get_uvarint(&b, &mut p), Some(v)); }
        for v in [0i64, -1, 1, -64, 64, i64::MIN, i64::MAX] { assert_eq!(get_svarint(&b, &mut p), Some(v)); }
        assert_eq!(p, b.len());
    }

    #[test]
    fn write_read_seek() {
        let dir = std::env::temp_dir().join(format!("tri-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.tri");
        let bodies: Vec<Vec<u8>> = (0..10_000u64).map(|i| format!("msg{i:05}xxxxxxxxxxxxxxxx").into_bytes()).collect();
        {
            let mut w = Writer::create(&p, 1000, 1).unwrap();
            for (i, b) in bodies.iter().enumerate() {
                let seq = i as u64 + 1;
                if (5000..5010).contains(&seq) { continue; } // a residual gap
                w.push(&rec(seq, b)).unwrap();
            }
            w.push_gap(7, 5000, 5009);
            let idx = w.finish().unwrap();
            assert_eq!(idx.messages, 9990);
            assert_eq!(idx.blocks.len(), 10);
            assert!(idx.compressed_bytes < idx.raw_bytes / 3, "zstd should crush this");
        }
        let mut s = Store::open(&p).unwrap();
        assert_eq!(s.index.gaps, vec![(7, GapRange { from: 5000, to: 5009 })]);
        // seq range across a block boundary and the gap
        let mut got = Vec::new();
        let n = s.read_seq_range(7, 4990, 5015, |r| { got.push((r.seq, r.body.to_vec(), r.site, r.capture_ns)); }).unwrap();
        assert_eq!(n, 16);
        assert_eq!(got.first().unwrap().0, 4990);
        assert_eq!(got.last().unwrap().0, 5015);
        assert!(got.iter().all(|g| !(5000..5010).contains(&g.0)));
        for (seq, body, site, cap) in &got {
            assert_eq!(body, &bodies[*seq as usize - 1]);
            assert_eq!(*site, (*seq % 2) as u8);
            assert_eq!(*cap, 1_000_000 + seq * 1000);
        }
        // only the overlapping blocks are touched
        assert_eq!(s.blocks_for_seq(7, 4990, 5015).len(), 2);
        assert_eq!(s.blocks_for_seq(7, 20_000, 30_000).len(), 0);
        // time range
        let n = s.read_time_range(1_000_000 + 2500 * 1000, 1_000_000 + 2600 * 1000, |r| assert!((2500..=2600).contains(&r.seq))).unwrap();
        assert_eq!(n, 101);
        assert_eq!(s.blocks_for_time(1_000_000 + 2500 * 1000, 1_000_000 + 2600 * 1000).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
