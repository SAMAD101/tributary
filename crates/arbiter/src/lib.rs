//! A/B arbitration: two redundant copies of the same sequenced feed (site A,
//! site B) in, one ordered, deduplicated, gap-free-where-possible stream out.
//!
//! Model (per session):
//! * `next` — the next sequence number to emit.
//! * A message with `seq == next` is emitted immediately, **borrowed** from the
//!   incoming segment (no copy). Whichever site delivers first "wins".
//! * `seq < next` — already emitted (duplicate) or already declared lost
//!   (`late_after_gap`); dropped either way.
//! * `seq > next` — the other site may still deliver the missing ones, so it is
//!   copied into a fixed-size reorder window (`window` slots, indexed `seq % window`).
//! * `frontier[site]` = highest `first_seq + count` seen from that site (a
//!   heartbeat advances it too). Once **both** frontiers are past `next`, no
//!   site can still deliver `next` in order → `[next, min(frontier)-1]` is
//!   declared a residual gap and buffered messages drain out.
//! * The window doubles as the max lag: if one site runs `window` messages
//!   ahead of `next` while the other is silent, we stop waiting.
//!
//! Hot path: no allocation (slots preallocated), no locks, no syscalls.
//! Reports are built on demand off the hot path.

pub mod pipeline;

use gapdetect::{GapDetector, GapRange, SessionReport};
use serde::Serialize;
use tp_parse::{Segment, TpHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Site { A = 0, B = 1 }

impl Site {
    #[inline]
    pub fn other(self) -> Site { if self == Site::A { Site::B } else { Site::A } }
    pub fn name(self) -> &'static str { if self == Site::A { "A" } else { "B" } }
}

/// INFO: fixed 128-byte reorder slots. IEX messages are ≤ 80 bytes; a
/// larger protocol needs a bigger `SLOT` (or a slab of segment payloads).
pub const SLOT: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Reorder window in messages; power of two. Also the max A/B lag.
    pub window: usize,
}
impl Default for Config {
    fn default() -> Self { Self { window: 1 << 16 } }
}

/// One emitted message.
#[derive(Debug, Clone, Copy)]
pub struct Out<'a> {
    pub session_id: u32,
    pub seq: u64,
    pub site: Site,
    /// True if it came out of the reorder window rather than straight from the wire.
    pub from_buffer: bool,
    pub body: &'a [u8],
    pub capture_ns: u64,
    pub send_ns: i64,
}

#[derive(Debug, Clone, Copy)]
pub enum Emit<'a> {
    Msg(Out<'a>),
    /// Residual gap: no site had these sequences.
    Gap { session_id: u32, from: u64, to: u64 },
}

#[derive(Clone, Copy)]
struct Slot {
    seq: u64,
    capture_ns: u64,
    send_ns: i64,
    len: u16,
    site: u8,
    used: bool,
    data: [u8; SLOT],
}
const EMPTY: Slot = Slot { seq: 0, capture_ns: 0, send_ns: 0, len: 0, site: 0, used: false, data: [0; SLOT] };

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SiteStats {
    pub segments: u64,
    pub msgs_in: u64,
    /// Emitted straight from this site's wire (this site delivered first).
    pub wins: u64,
    /// Emitted from the reorder window, having been buffered from this site.
    pub wins_from_buffer: u64,
    pub buffered: u64,
    pub dups: u64,
    /// Arrived after the range was already declared a residual gap.
    pub late_after_gap: u64,
    /// Could not be buffered (body > SLOT bytes); dropped from this site.
    pub oversize: u64,
}

struct Session {
    id: u32,
    next: u64,
    anchored: bool,
    emitted: u64,
    frontier: [u64; 2],
    stats: [SiteStats; 2],
    gaps: Vec<GapRange>,
    missing: u64,
    forced_advances: u64,
    slots: Vec<Slot>,
    mask: usize,
}

pub struct Arbiter {
    cfg: Config,
    sessions: Vec<Session>,
    /// Independent per-site sequence tracking (what each site itself lost).
    gapdet: [GapDetector; 2],
}

impl Arbiter {
    pub fn new(cfg: Config) -> Self {
        assert!(cfg.window.is_power_of_two() && cfg.window >= 2);
        Self { cfg, sessions: Vec::new(), gapdet: [GapDetector::new(), GapDetector::new()] }
    }

    #[inline]
    fn session(&mut self, h: &TpHeader) -> usize {
        if let Some(i) = self.sessions.iter().position(|s| s.id == h.session_id) {
            return i;
        }
        self.sessions.push(Session {
            id: h.session_id, next: h.first_seq, anchored: false, emitted: 0, frontier: [0, 0], stats: Default::default(),
            gaps: Vec::with_capacity(1024), missing: 0, forced_advances: 0,
            slots: vec![EMPTY; self.cfg.window], mask: self.cfg.window - 1,
        });
        self.sessions.len() - 1
    }

    /// Feed one segment from `site`, captured at `capture_ns`.
    #[inline]
    pub fn push(&mut self, site: Site, seg: &Segment<'_>, capture_ns: u64, out: &mut dyn FnMut(Emit<'_>)) {
        let h = &seg.header;
        self.gapdet[site as usize].observe(h, capture_ns);
        let idx = self.session(h);
        let s = &mut self.sessions[idx];
        let si = site as usize;
        s.stats[si].segments += 1;
        let f = &mut s.frontier[si];
        if h.next_seq() > *f { *f = h.next_seq(); }

        // Session start: until BOTH sites have shown up (or one hits EOF /
        // the window fills), nothing is emitted, so a site that lost the very
        // first packets can still be covered by the other. While un-anchored,
        // the start may still move backwards.
        if s.emitted == 0 && h.first_seq < s.next {
            s.next = h.first_seq;
        }
        let anchored = s.frontier[0] != 0 && s.frontier[1] != 0;
        if anchored && !s.anchored {
            s.anchored = true;
            s.drain(out);
        }
        for r in seg.messages() {
            let Ok((seq, body)) = r else { break };
            s.stats[si].msgs_in += 1;
            if seq < s.next {
                if in_gaps(&s.gaps, seq) { s.stats[si].late_after_gap += 1 } else { s.stats[si].dups += 1 }
                continue;
            }
            if seq == s.next && s.anchored {
                s.stats[si].wins += 1;
                s.next += 1;
                s.emitted += 1;
                out(Emit::Msg(Out { session_id: s.id, seq, site, from_buffer: false, body, capture_ns, send_ns: h.send_time }));
                s.drain(out);
                continue;
            }
            // seq > next: park it in the window.
            if seq - s.next >= s.slots.len() as u64 {
                s.forced_advances += 1;
                let x = seq - s.slots.len() as u64 + 1;
                s.advance_to(x, out);
            }
            let slot = &mut s.slots[(seq & s.mask as u64) as usize];
            if slot.used {
                debug_assert_eq!(slot.seq, seq);
                s.stats[si].dups += 1;
                continue;
            }
            if body.len() > SLOT {
                s.stats[si].oversize += 1;
                continue;
            }
            slot.used = true;
            slot.seq = seq;
            slot.len = body.len() as u16;
            slot.site = si as u8;
            slot.capture_ns = capture_ns;
            slot.send_ns = h.send_time;
            slot.data[..body.len()].copy_from_slice(body);
            s.stats[si].buffered += 1;
        }
        s.resolve(out);
    }

    /// Declare a site finished (file EOF / site down): it will never deliver again.
    pub fn eof(&mut self, site: Site, out: &mut dyn FnMut(Emit<'_>)) {
        for s in &mut self.sessions {
            s.frontier[site as usize] = u64::MAX;
            s.resolve(out);
        }
    }

    /// Flush everything (both sites finished).
    pub fn finish(&mut self, out: &mut dyn FnMut(Emit<'_>)) {
        self.eof(Site::A, out);
        self.eof(Site::B, out);
    }

    pub fn report(&self) -> Report {
        Report {
            sessions: self.sessions.iter().map(|s| {
                let site_gaps = |site: usize| self.gapdet[site].sessions().find(|r| r.session_id == s.id).map(|r| r.gaps.clone()).unwrap_or_default();
                let (ga, gb) = (site_gaps(0), site_gaps(1));
                SessionArb {
                    session_id: s.id,
                    emitted: s.emitted,
                    first_seq: s.next.saturating_sub(s.emitted + s.missing),
                    next_seq: s.next,
                    site: s.stats,
                    residual_gaps: s.gaps.clone(),
                    residual_missing: s.missing,
                    forced_advances: s.forced_advances,
                    recovered_from_b: subtract(&ga, &s.gaps),
                    recovered_from_a: subtract(&gb, &s.gaps),
                    site_a_gaps: ga,
                    site_b_gaps: gb,
                }
            }).collect(),
            site_a: self.gapdet[0].report(),
            site_b: self.gapdet[1].report(),
        }
    }
}

impl Session {
    /// Emit buffered messages while the window holds `next`.
    #[inline]
    fn drain(&mut self, out: &mut dyn FnMut(Emit<'_>)) {
        loop {
            let i = (self.next & self.mask as u64) as usize;
            let slot = &mut self.slots[i];
            if !slot.used { return; }
            debug_assert_eq!(slot.seq, self.next);
            slot.used = false;
            let site = if slot.site == 0 { Site::A } else { Site::B };
            self.stats[slot.site as usize].wins_from_buffer += 1;
            let seq = self.next;
            self.next += 1;
            self.emitted += 1;
            out(Emit::Msg(Out { session_id: self.id, seq, site, from_buffer: true, body: &slot.data[..slot.len as usize], capture_ns: slot.capture_ns, send_ns: slot.send_ns }));
        }
    }

    /// Both sites are past `next` ⇒ declare what is missing up to min(frontier).
    #[inline]
    fn resolve(&mut self, out: &mut dyn FnMut(Emit<'_>)) {
        let f = self.frontier[0].min(self.frontier[1]);
        if f == u64::MAX {
            // both finished: flush the whole window
            let end = self.slots.iter().filter(|s| s.used).map(|s| s.seq + 1).max().unwrap_or(self.next);
            self.advance_to(end, out);
        } else if f > self.next {
            self.advance_to(f, out);
        }
    }

    /// Move `next` up to `x`, emitting buffered messages and recording holes as residual gaps.
    fn advance_to(&mut self, x: u64, out: &mut dyn FnMut(Emit<'_>)) {
        let mut gap: Option<u64> = None;
        while self.next < x {
            let i = (self.next & self.mask as u64) as usize;
            if self.slots[i].used {
                if let Some(from) = gap.take() { self.record_gap(from, self.next - 1, out); }
                self.drain(out); // emits this and any contiguous run
            } else {
                gap.get_or_insert(self.next);
                self.next += 1;
            }
        }
        if let Some(from) = gap.take() { self.record_gap(from, self.next - 1, out); }
        self.anchored = true; // a forced/EOF advance commits the start too
        self.drain(out);
    }

    fn record_gap(&mut self, from: u64, to: u64, out: &mut dyn FnMut(Emit<'_>)) {
        match self.gaps.last_mut() {
            Some(l) if l.to + 1 == from => l.to = to,
            _ => self.gaps.push(GapRange { from, to }),
        }
        self.missing += to - from + 1;
        out(Emit::Gap { session_id: self.id, from, to });
    }
}

#[inline]
fn in_gaps(gaps: &[GapRange], seq: u64) -> bool {
    // gaps are ascending; late arrivals are near the end
    gaps.iter().rev().take_while(|g| g.to >= seq).any(|g| g.from <= seq)
}

/// `a \ b` for ascending, disjoint range lists.
pub fn subtract(a: &[GapRange], b: &[GapRange]) -> Vec<GapRange> {
    let mut out = Vec::new();
    for g in a {
        let mut cur = g.from;
        for h in b.iter().filter(|h| h.to >= g.from && h.from <= g.to) {
            if h.from > cur { out.push(GapRange { from: cur, to: h.from - 1 }); }
            cur = cur.max(h.to + 1);
        }
        if cur <= g.to { out.push(GapRange { from: cur, to: g.to }); }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionArb {
    pub session_id: u32,
    pub emitted: u64,
    pub first_seq: u64,
    pub next_seq: u64,
    pub site: [SiteStats; 2],
    pub residual_gaps: Vec<GapRange>,
    pub residual_missing: u64,
    pub forced_advances: u64,
    /// Ranges site A lost that site B supplied, and vice versa.
    pub recovered_from_b: Vec<GapRange>,
    pub recovered_from_a: Vec<GapRange>,
    pub site_a_gaps: Vec<GapRange>,
    pub site_b_gaps: Vec<GapRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub sessions: Vec<SessionArb>,
    pub site_a: Vec<SessionReport>,
    pub site_b: Vec<SessionReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg_bytes(first_seq: u64, n: u16, send: i64) -> Vec<u8> {
        let mut payload = Vec::new();
        for i in 0..n {
            let mut m = vec![b'E', b'x'];
            m.extend_from_slice(&(send + i as i64).to_le_bytes());
            m.extend_from_slice(b"SYM     ");
            payload.extend_from_slice(&(m.len() as u16).to_le_bytes());
            payload.extend_from_slice(&m);
        }
        let mut b = vec![1u8, 0, 0x04, 0x80];
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&first_seq.to_le_bytes());
        b.extend_from_slice(&send.to_le_bytes());
        b.extend_from_slice(&payload);
        b
    }

    fn run(events: &[(Site, u64, u16)], finish: bool) -> (Vec<(u64, Site)>, Vec<GapRange>, Arbiter) {
        let mut arb = Arbiter::new(Config { window: 16 });
        let mut got = Vec::new();
        let mut gaps = Vec::new();
        let mut out = |e: Emit<'_>| match e {
            Emit::Msg(m) => got.push((m.seq, m.site)),
            Emit::Gap { from, to, .. } => gaps.push(GapRange { from, to }),
        };
        for (i, &(site, first, n)) in events.iter().enumerate() {
            let b = seg_bytes(first, n, i as i64);
            arb.push(site, &Segment::parse(&b).unwrap(), i as u64, &mut out);
        }
        if finish { arb.finish(&mut out); }
        (got, gaps, arb)
    }

    #[test]
    fn a_drops_b_recovers() {
        use Site::*;
        // A: 1-3, (drops 4-6), 7-9 ; B: 1-3, 4-6, 7-9 (B slightly later)
        let (got, gaps, arb) = run(&[(A, 1, 3), (B, 1, 3), (A, 7, 3), (B, 4, 3), (B, 7, 3)], true);
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), (1..=9).collect::<Vec<_>>());
        assert_eq!(got[3].1, B); // 4 came from B
        assert_eq!(got[6].1, A); // 7 was buffered from A, drained after B filled 4-6
        assert!(gaps.is_empty());
        let r = &arb.report().sessions[0];
        // 1-3 from A were held until B showed up (start anchoring), then drained from the window
        assert_eq!(r.site[0].wins + r.site[0].wins_from_buffer, 6);
        assert_eq!(r.site[1].wins, 3);
        assert_eq!(r.site[1].dups, 6);
        assert_eq!(r.recovered_from_b, vec![GapRange { from: 4, to: 6 }]);
        assert!(r.recovered_from_a.is_empty());
    }

    #[test]
    fn both_drop_residual_gap() {
        use Site::*;
        let (got, gaps, arb) = run(&[(A, 1, 3), (B, 1, 3), (A, 7, 3), (B, 7, 3), (A, 10, 1)], false);
        // once B's frontier passes 4 as well, 4-6 is declared lost and 7-9 drains
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), vec![1, 2, 3, 7, 8, 9, 10]);
        assert_eq!(gaps, vec![GapRange { from: 4, to: 6 }]);
        assert_eq!(arb.report().sessions[0].residual_missing, 3);
        // a late copy of 4-6 now counts as late_after_gap, not dup
        let mut arb = arb;
        let b = seg_bytes(4, 3, 99);
        arb.push(B, &Segment::parse(&b).unwrap(), 99, &mut |_| {});
        assert_eq!(arb.report().sessions[0].site[1].late_after_gap, 3);
    }

    #[test]
    fn heartbeat_advances_frontier_and_eof_flushes() {
        use Site::*;
        // A drops 4-6 and B is silent for them, but B's heartbeat says next=7 → lost.
        let (got, gaps, _) = run(&[(A, 1, 3), (B, 1, 3), (A, 7, 3), (B, 7, 0)], false);
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), vec![1, 2, 3, 7, 8, 9]);
        assert_eq!(gaps, vec![GapRange { from: 4, to: 6 }]);
        // eof of B while A has buffered data → flush via A alone
        let (got, gaps, _) = run(&[(A, 1, 3), (A, 7, 3)], true);
        assert_eq!(got.len(), 6);
        assert_eq!(gaps, vec![GapRange { from: 4, to: 6 }]);
    }

    #[test]
    fn window_overflow_forces_advance() {
        use Site::*;
        // window 16: A jumps 40 ahead while B silent → forced gap
        let (got, gaps, arb) = run(&[(A, 1, 2), (A, 40, 2)], false);
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(gaps.iter().map(|g| g.len()).sum::<u64>(), 23);
        assert_eq!(arb.report().sessions[0].residual_gaps, vec![GapRange { from: 3, to: 25 }]); // next moved to 41-16+1 = 26
        assert_eq!(arb.report().sessions[0].forced_advances, 2);
    }

    #[test]
    fn late_start_rewinds() {
        use Site::*;
        let (got, gaps, _) = run(&[(A, 5, 2), (B, 1, 2), (B, 3, 2), (B, 5, 2)], true);
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
        assert!(gaps.is_empty());
    }

    #[test]
    fn subtract_ranges() {
        let g = |a, b| GapRange { from: a, to: b };
        assert_eq!(subtract(&[g(1, 10)], &[g(3, 4), g(8, 12)]), vec![g(1, 2), g(5, 7)]);
        assert_eq!(subtract(&[g(1, 10)], &[]), vec![g(1, 10)]);
        assert_eq!(subtract(&[g(1, 10)], &[g(0, 20)]), vec![]);
    }
}
