//! Per-session sequence tracking for IEX-TP segments.
//!
//! IEX-TP semantics: a segment carries `first_seq` and `message_count`; the
//! next segment must start at `first_seq + message_count`. Heartbeats
//! (`message_count == 0`) carry the next expected sequence, so they detect
//! gaps too. Sequences restart per session (session_id changes).
//!
//! Hot path is [`GapDetector::observe`]: a session lookup (linear scan over a
//! handful of sessions), a compare, and — only when something is wrong — a push
//! onto a pre-reserved gap list. No allocation in the steady state.

use serde::{Deserialize, Serialize};
use tp_parse::TpHeader;

/// Inclusive range of missing sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapRange {
    pub from: u64,
    pub to: u64,
}
impl GapRange {
    #[inline]
    pub fn len(&self) -> u64 { self.to - self.from + 1 }
    #[inline]
    pub fn is_empty(&self) -> bool { self.to < self.from }
}

/// What a single segment observation meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Segment was exactly the next expected one (or a heartbeat confirming it).
    InOrder,
    /// Segment jumped ahead; `missing` messages were skipped (gap recorded).
    Gap { missing: u64 },
    /// Segment (fully or partially) filled a previously recorded gap: late/reordered.
    Reordered { filled: u64 },
    /// Segment's sequences were all already seen.
    Duplicate,
    /// First segment for this session.
    Start,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionReport {
    pub session_id: u32,
    pub channel_id: u32,
    pub message_protocol_id: u16,
    pub segments: u64,
    pub heartbeats: u64,
    pub messages: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    /// Next sequence number the session expects (last_seq + 1 in a clean stream).
    pub expected_next: u64,
    /// Sum of message_count over segments classed as duplicates (fully seen).
    pub duplicate_msgs: u64,
    pub duplicate_segments: u64,
    pub reordered_segments: u64,
    /// Total messages recovered by late (reordered) segments.
    pub reordered_msgs: u64,
    pub gap_count: usize,
    pub missing_msgs: u64,
    pub gaps: Vec<GapRange>,
    /// Capture-timestamp span, ns since epoch.
    pub first_capture_ns: u64,
    pub last_capture_ns: u64,
    /// IEX send-time span, ns since epoch.
    pub first_send_ns: i64,
    pub last_send_ns: i64,
}

impl SessionReport {
    pub fn capture_span_ns(&self) -> u64 { self.last_capture_ns.saturating_sub(self.first_capture_ns) }
    pub fn send_span_ns(&self) -> i64 { self.last_send_ns - self.first_send_ns }
}

#[derive(Debug, Clone)]
struct Session {
    r: SessionReport,
}

#[derive(Debug, Default, Clone)]
pub struct GapDetector {
    sessions: Vec<Session>,
}

impl GapDetector {
    pub fn new() -> Self { Self::default() }

    /// Observe one segment header captured at `capture_ns`.
    #[inline]
    pub fn observe(&mut self, h: &TpHeader, capture_ns: u64) -> Event {
        let idx = match self.sessions.iter().position(|s| s.r.session_id == h.session_id) {
            Some(i) => i,
            None => {
                self.sessions.push(Session { r: SessionReport {
                    session_id: h.session_id, channel_id: h.channel_id, message_protocol_id: h.message_protocol_id,
                    segments: 0, heartbeats: 0, messages: 0, first_seq: h.first_seq, last_seq: h.first_seq.saturating_sub(1),
                    expected_next: h.first_seq, duplicate_msgs: 0, duplicate_segments: 0, reordered_segments: 0, reordered_msgs: 0,
                    gap_count: 0, missing_msgs: 0, gaps: Vec::with_capacity(1024),
                    first_capture_ns: capture_ns, last_capture_ns: capture_ns, first_send_ns: h.send_time, last_send_ns: h.send_time,
                }});
                let s = &mut self.sessions.last_mut().unwrap().r;
                s.segments = 1;
                if h.message_count == 0 { s.heartbeats = 1; } else { s.messages = h.message_count as u64; s.last_seq = h.next_seq() - 1; }
                s.expected_next = h.next_seq();
                return Event::Start;
            }
        };
        let s = &mut self.sessions[idx].r;
        s.segments += 1;
        s.last_capture_ns = capture_ns;
        s.last_send_ns = h.send_time;
        let n = h.message_count as u64;
        if n == 0 {
            s.heartbeats += 1;
        }
        let first = h.first_seq;
        let end = h.next_seq(); // exclusive
        if first == s.expected_next {
            s.messages += n;
            if n > 0 { s.last_seq = end - 1; }
            s.expected_next = end;
            return Event::InOrder;
        }
        if first > s.expected_next {
            let missing = first - s.expected_next;
            s.gaps.push(GapRange { from: s.expected_next, to: first - 1 });
            s.gap_count += 1;
            s.missing_msgs += missing;
            s.messages += n;
            if n > 0 { s.last_seq = end - 1; }
            s.expected_next = end;
            return Event::Gap { missing };
        }
        // first < expected_next: late segment. Fill any recorded gaps it overlaps.
        if n == 0 {
            // stale heartbeat — harmless
            return Event::Duplicate;
        }
        let filled = fill_gaps(&mut s.gaps, first, end - 1);
        if filled > 0 {
            s.gap_count = s.gaps.len();
            s.missing_msgs -= filled;
            s.messages += filled;
            s.reordered_segments += 1;
            s.reordered_msgs += filled;
            if end > s.expected_next {
                // overlaps the frontier too (rare): advance
                s.messages += end - s.expected_next;
                s.last_seq = end - 1;
                s.expected_next = end;
            }
            Event::Reordered { filled }
        } else {
            s.duplicate_segments += 1;
            s.duplicate_msgs += n;
            Event::Duplicate
        }
    }

    pub fn sessions(&self) -> impl Iterator<Item = &SessionReport> { self.sessions.iter().map(|s| &s.r) }
    pub fn report(&self) -> Vec<SessionReport> { self.sessions().cloned().collect() }
    pub fn total_messages(&self) -> u64 { self.sessions().map(|s| s.messages).sum() }
    pub fn total_missing(&self) -> u64 { self.sessions().map(|s| s.missing_msgs).sum() }
}

/// Remove `[lo, hi]` from `gaps` (which are disjoint, ascending). Returns how
/// many missing sequence numbers were filled. Splits ranges as needed.
/// INFO: linear scan from the newest gap backwards; late packets are close
/// to the frontier so this is O(1) in practice. Upgrade to a BTreeMap if a
/// feed ever has thousands of open gaps.
fn fill_gaps(gaps: &mut Vec<GapRange>, lo: u64, hi: u64) -> u64 {
    let mut filled = 0;
    let mut i = gaps.len();
    while i > 0 {
        i -= 1;
        let g = gaps[i];
        if g.to < lo {
            break; // everything earlier is below the segment
        }
        if g.from > hi {
            continue;
        }
        let flo = lo.max(g.from);
        let fhi = hi.min(g.to);
        filled += fhi - flo + 1;
        match (flo > g.from, fhi < g.to) {
            (false, false) => { gaps.remove(i); }
            (true, false) => gaps[i].to = flo - 1,
            (false, true) => gaps[i].from = fhi + 1,
            (true, true) => {
                gaps[i].to = flo - 1;
                gaps.insert(i + 1, GapRange { from: fhi + 1, to: g.to });
            }
        }
    }
    filled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(session: u32, first_seq: u64, count: u16) -> TpHeader {
        TpHeader { version: 1, message_protocol_id: 0x8004, channel_id: 1, session_id: session, payload_length: 0, message_count: count, stream_offset: 0, first_seq, send_time: first_seq as i64 }
    }

    #[test]
    fn clean_stream() {
        let mut d = GapDetector::new();
        assert_eq!(d.observe(&hdr(1, 1, 3), 0), Event::Start);
        assert_eq!(d.observe(&hdr(1, 4, 0), 1), Event::InOrder); // heartbeat
        assert_eq!(d.observe(&hdr(1, 4, 2), 2), Event::InOrder);
        let r = &d.report()[0];
        assert_eq!((r.messages, r.first_seq, r.last_seq, r.gap_count, r.heartbeats), (5, 1, 5, 0, 1));
    }

    #[test]
    fn gap_dup_reorder() {
        let mut d = GapDetector::new();
        d.observe(&hdr(1, 1, 2), 0);
        assert_eq!(d.observe(&hdr(1, 10, 1), 1), Event::Gap { missing: 7 }); // 3..=9 missing
        assert_eq!(d.observe(&hdr(1, 10, 1), 2), Event::Duplicate);
        assert_eq!(d.observe(&hdr(1, 5, 2), 3), Event::Reordered { filled: 2 }); // fills 5,6 → gaps 3..4, 7..9
        assert_eq!(d.observe(&hdr(1, 3, 2), 3), Event::Reordered { filled: 2 }); // → 7..9
        assert_eq!(d.observe(&hdr(1, 7, 3), 3), Event::Reordered { filled: 3 }); // → none
        let r = &d.report()[0];
        assert_eq!(r.gaps, vec![]);
        assert_eq!((r.missing_msgs, r.duplicate_segments, r.reordered_segments, r.messages), (0, 1, 3, 10));
        // heartbeat pointing past the frontier is also a gap
        assert_eq!(d.observe(&hdr(1, 15, 0), 4), Event::Gap { missing: 4 });
        assert_eq!(d.report()[0].gaps, vec![GapRange { from: 11, to: 14 }]);
    }

    #[test]
    fn sessions_are_independent() {
        let mut d = GapDetector::new();
        d.observe(&hdr(1, 1, 2), 0);
        assert_eq!(d.observe(&hdr(2, 1, 2), 0), Event::Start);
        assert_eq!(d.observe(&hdr(1, 3, 2), 0), Event::InOrder);
        assert_eq!(d.report().len(), 2);
    }
}
