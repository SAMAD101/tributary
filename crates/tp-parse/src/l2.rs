//! Ethernet → IPv4/IPv6 → UDP walk using `etherparse`, returning the borrowed UDP payload.

use etherparse::{SlicedPacket, TransportSlice};

/// L2–L4 header lengths for the common IEX case (Ethernet II + IPv4 no options + UDP).
pub const ETH_IPV4_UDP_HEADERS: usize = 14 + 20 + 8;

/// Return the UDP payload of an Ethernet frame, or `None` if it is not UDP.
#[inline]
pub fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    match SlicedPacket::from_ethernet(frame) {
        Ok(SlicedPacket { transport: Some(TransportSlice::Udp(udp)), .. }) => Some(udp.payload()),
        _ => None,
    }
}

/// Fast path for the exact frame shape IEX sends (Ethernet II, IPv4 without
/// options, UDP). Falls back to the full `etherparse` walk for anything else.
///
/// The check is: ethertype == 0x0800, IHL == 5, protocol == 17, and the UDP
/// length field agrees with the frame length. Any mismatch → generic path.
#[inline]
pub fn udp_payload_fast(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() >= ETH_IPV4_UDP_HEADERS
        && frame[12] == 0x08 && frame[13] == 0x00 // IPv4
        && frame[14] == 0x45                       // version 4, IHL 5
        && frame[23] == 17                         // UDP
    {
        let udp_len = u16::from_be_bytes([frame[38], frame[39]]) as usize;
        if udp_len >= 8 && 34 + udp_len <= frame.len() {
            return Some(&frame[ETH_IPV4_UDP_HEADERS..34 + udp_len]);
        }
    }
    udp_payload(frame)
}
