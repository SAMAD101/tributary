//! IEX-TP v1.0 + DEEP 1.0 / TOPS 1.6 parsing over borrowed byte slices.
//!
//! Hot path rules: no allocation, no syscalls, no locks. Every parse is a
//! bounds check followed by a `#[repr(C, packed)]` unaligned read.
//!
//! # Field layouts (verify against the IEX specs)
//! IEX-TP header, 40 bytes, all little-endian (IEX-TP v1.0 §"Segment Header"):
//! ```text
//! off size field
//!   0    1 Version (0x01)
//!   1    1 Reserved
//!   2    2 Message Protocol ID (0x8003 = TOPS 1.6, 0x8004 = DEEP 1.0)
//!   4    4 Channel ID
//!   8    4 Session ID
//!  12    2 Payload Length
//!  14    2 Message Count
//!  16    8 Stream Offset
//!  24    8 First Message Sequence Number
//!  32    8 Send Time (ns since Unix epoch)
//! ```
//! Payload = `Message Count` × { u16 length, message bytes }. Message `i` in a
//! segment has sequence number `first_seq + i`.
//!
//! These offsets were cross-checked against rob-blackbourn/iex_parser
//! (`struct '<BxHIIHHqqq'`) and against real HIST data (see `tests/golden.rs`).

pub mod l2;
pub mod msg;

pub use msg::{decode, Message};

use core::mem::size_of;

pub const TP_HEADER_LEN: usize = 40;
pub const PROTO_TOPS_1_5: u16 = 0x8002;
pub const PROTO_TOPS_1_6: u16 = 0x8003;
pub const PROTO_DEEP_1_0: u16 = 0x8004;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum ParseError {
    #[error("buffer too short: need {need}, have {have}")]
    Short { need: usize, have: usize },
    #[error("unsupported IEX-TP version {0}")]
    Version(u8),
    #[error("payload length {declared} does not match buffer {actual}")]
    PayloadLen { declared: usize, actual: usize },
    #[error("message length {len} overruns payload at offset {off}")]
    MessageLen { off: usize, len: usize },
    #[error("unknown message type {0:#x}")]
    UnknownType(u8),
}

/// Marker for plain-old-data structs that may be read from any byte pattern.
///
/// # Safety
/// Implementors must be `#[repr(C, packed)]` and consist only of integer fields
/// (no padding, no invariants), so `read_unaligned` from arbitrary bytes is sound.
pub(crate) unsafe trait Pod: Copy {}

/// Read a `Pod` from the front of `b`. One bounds check, then an unaligned copy.
#[inline(always)]
pub(crate) fn read_pod<T: Pod>(b: &[u8]) -> Result<T, ParseError> {
    if b.len() < size_of::<T>() {
        return Err(ParseError::Short { need: size_of::<T>(), have: b.len() });
    }
    // SAFETY: length checked above; T is Pod (packed, integer-only), so any
    // bit pattern is a valid T and unaligned access is permitted.
    Ok(unsafe { core::ptr::read_unaligned(b.as_ptr() as *const T) })
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RawTpHeader {
    version: u8,
    reserved: u8,
    message_protocol_id: u16,
    channel_id: u32,
    session_id: u32,
    payload_length: u16,
    message_count: u16,
    stream_offset: u64,
    first_seq: u64,
    send_time: i64,
}
unsafe impl Pod for RawTpHeader {}
const _: () = assert!(size_of::<RawTpHeader>() == TP_HEADER_LEN);

/// Decoded IEX-TP segment header (host byte order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpHeader {
    pub version: u8,
    pub message_protocol_id: u16,
    pub channel_id: u32,
    pub session_id: u32,
    pub payload_length: u16,
    pub message_count: u16,
    pub stream_offset: u64,
    /// Sequence number of the first message in this segment. A heartbeat
    /// (message_count == 0) carries the *next expected* sequence number.
    pub first_seq: u64,
    /// Send time, ns since Unix epoch (the "packet send time" timestamp).
    pub send_time: i64,
}

impl TpHeader {
    /// Sequence number one past the last message in this segment.
    #[inline]
    pub fn next_seq(&self) -> u64 {
        self.first_seq + self.message_count as u64
    }
}

/// A parsed IEX-TP segment borrowing the UDP payload.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub header: TpHeader,
    payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Parse a UDP payload as an IEX-TP segment. Validates version and that
    /// the declared payload length matches the buffer exactly.
    #[inline]
    pub fn parse(udp_payload: &'a [u8]) -> Result<Self, ParseError> {
        let raw: RawTpHeader = read_pod(udp_payload)?;
        if raw.version != 1 {
            return Err(ParseError::Version(raw.version));
        }
        let header = TpHeader {
            version: raw.version,
            message_protocol_id: u16::from_le(raw.message_protocol_id),
            channel_id: u32::from_le(raw.channel_id),
            session_id: u32::from_le(raw.session_id),
            payload_length: u16::from_le(raw.payload_length),
            message_count: u16::from_le(raw.message_count),
            stream_offset: u64::from_le(raw.stream_offset),
            first_seq: u64::from_le(raw.first_seq),
            send_time: i64::from_le(raw.send_time),
        };
        let payload = &udp_payload[TP_HEADER_LEN..];
        if payload.len() != header.payload_length as usize {
            return Err(ParseError::PayloadLen { declared: header.payload_length as usize, actual: payload.len() });
        }
        Ok(Segment { header, payload })
    }

    /// Raw payload bytes (length-prefixed messages).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Iterate `(sequence_number, raw_message_bytes)` without decoding.
    #[inline]
    pub fn messages(&self) -> MessageIter<'a> {
        MessageIter { buf: self.payload, off: 0, seq: self.header.first_seq, remaining: self.header.message_count }
    }
}

/// Zero-alloc iterator over the length-prefixed messages of a segment.
pub struct MessageIter<'a> {
    buf: &'a [u8],
    off: usize,
    seq: u64,
    remaining: u16,
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = Result<(u64, &'a [u8]), ParseError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let b = &self.buf[self.off.min(self.buf.len())..];
        if b.len() < 2 {
            self.remaining = 0;
            return Some(Err(ParseError::Short { need: 2, have: b.len() }));
        }
        let len = u16::from_le_bytes([b[0], b[1]]) as usize;
        if b.len() < 2 + len {
            self.remaining = 0;
            return Some(Err(ParseError::MessageLen { off: self.off, len }));
        }
        let msg = &b[2..2 + len];
        self.off += 2 + len;
        let seq = self.seq;
        self.seq += 1;
        Some(Ok((seq, msg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(msgs: &[&[u8]], first_seq: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        for m in msgs {
            payload.extend_from_slice(&(m.len() as u16).to_le_bytes());
            payload.extend_from_slice(m);
        }
        let mut b = vec![1u8, 0];
        b.extend_from_slice(&PROTO_DEEP_1_0.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0xABCDu32.to_le_bytes());
        b.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        b.extend_from_slice(&(msgs.len() as u16).to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&first_seq.to_le_bytes());
        b.extend_from_slice(&1_577_000_000_000_000_000i64.to_le_bytes());
        b.extend_from_slice(&payload);
        b
    }

    #[test]
    fn header_and_messages() {
        let b = seg(&[b"\x53R\0\0\0\0\0\0\0\0", b"hello"], 100);
        let s = Segment::parse(&b).unwrap();
        assert_eq!(s.header.message_protocol_id, PROTO_DEEP_1_0);
        assert_eq!(s.header.session_id, 0xABCD);
        assert_eq!(s.header.first_seq, 100);
        assert_eq!(s.header.next_seq(), 102);
        let v: Vec<_> = s.messages().map(|r| r.unwrap()).collect();
        assert_eq!(v, vec![(100, &b"\x53R\0\0\0\0\0\0\0\0"[..]), (101, &b"hello"[..])]);
    }

    #[test]
    fn heartbeat() {
        let b = seg(&[], 7);
        let s = Segment::parse(&b).unwrap();
        assert_eq!(s.header.message_count, 0);
        assert_eq!(s.header.next_seq(), 7);
        assert_eq!(s.messages().count(), 0);
    }

    #[test]
    fn errors() {
        assert_eq!(Segment::parse(&[1u8; 10]).unwrap_err(), ParseError::Short { need: 40, have: 10 });
        let mut b = seg(&[], 1);
        b[0] = 2;
        assert_eq!(Segment::parse(&b).unwrap_err(), ParseError::Version(2));
        let mut b = seg(&[b"abc"], 1);
        b.push(0);
        assert!(matches!(Segment::parse(&b).unwrap_err(), ParseError::PayloadLen { .. }));
        // message length overruns payload
        let mut b = seg(&[b"abc"], 1);
        b[40] = 200;
        let s = Segment::parse(&b).unwrap();
        assert!(matches!(s.messages().next().unwrap().unwrap_err(), ParseError::MessageLen { .. }));
    }
}
