//! Fan a single packet stream into "site A" and "site B", each with its own
//! independent, seeded random packet loss (and optional delay/jitter so the two
//! sites' capture timestamps interleave like real geographically separate
//! feeds). Records exactly which sequence numbers each site dropped — the
//! ground truth the arbiter test is checked against.

use std::io;
use std::path::Path;

use capture::{CaptureSource, PcapFile, PcapWriter};
use gapdetect::GapRange;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use tp_parse::{l2, Segment, TpHeader};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SplitConfig {
    /// Probability of dropping any given packet on site A / B.
    pub loss_a: f64,
    pub loss_b: f64,
    pub seed: u64,
    /// Constant capture-time offset applied to each site (ns). Site B is
    /// usually the "far" datacenter → positive delay.
    pub delay_a_ns: i64,
    pub delay_b_ns: i64,
    /// Uniform jitter ±jitter_ns added per packet per site. Timestamps stay
    /// monotone within a site (a single multicast path preserves order), so
    /// jitter only changes *cross-site* interleaving.
    pub jitter_ns: u64,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self { loss_a: 0.01, loss_b: 0.01, seed: 42, delay_a_ns: 0, delay_b_ns: 200_000, jitter_ns: 20_000 }
    }
}

/// Ground truth: what each site dropped, as inclusive message-sequence ranges
/// (dropping a heartbeat loses no messages and is not recorded here).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Truth {
    pub packets_in: u64,
    pub messages_in: u64,
    pub packets_a: u64,
    pub packets_b: u64,
    pub dropped_pkts_a: u64,
    pub dropped_pkts_b: u64,
    pub dropped_a: Vec<GapRange>,
    pub dropped_b: Vec<GapRange>,
    /// dropped_a ∩ dropped_b: what no site had — the arbiter can never recover these.
    pub dropped_both: Vec<GapRange>,
}

fn push_merged(v: &mut Vec<GapRange>, g: GapRange) {
    match v.last_mut() {
        Some(l) if l.to + 1 == g.from => l.to = g.to,
        _ => v.push(g),
    }
}

/// Intersect two ascending, disjoint range lists.
pub fn intersect(a: &[GapRange], b: &[GapRange]) -> Vec<GapRange> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        let lo = a[i].from.max(b[j].from);
        let hi = a[i].to.min(b[j].to);
        if lo <= hi { push_merged(&mut out, GapRange { from: lo, to: hi }); }
        if a[i].to < b[j].to { i += 1 } else { j += 1 }
    }
    out
}

/// Per-packet routing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub keep_a: bool,
    pub keep_b: bool,
    pub ts_a: u64,
    pub ts_b: u64,
}

pub struct Splitter {
    cfg: SplitConfig,
    rng_a: ChaCha8Rng,
    rng_b: ChaCha8Rng,
    last_ts: [u64; 2],
    pub truth: Truth,
}

impl Splitter {
    pub fn new(cfg: SplitConfig) -> Self {
        Self { cfg, rng_a: ChaCha8Rng::seed_from_u64(cfg.seed), rng_b: ChaCha8Rng::seed_from_u64(cfg.seed ^ 0x0005_eedb), last_ts: [0; 2], truth: Truth::default() }
    }

    fn jitter(rng: &mut ChaCha8Rng, ts: u64, delay: i64, jitter: u64) -> u64 {
        let j = if jitter == 0 { 0 } else { rng.random_range(-(jitter as i64)..=jitter as i64) };
        (ts as i64 + delay + j).max(0) as u64
    }

    /// Decide routing for one packet and record ground truth.
    pub fn route(&mut self, h: &TpHeader, capture_ns: u64) -> Route {
        let keep_a = self.rng_a.random::<f64>() >= self.cfg.loss_a;
        let keep_b = self.rng_b.random::<f64>() >= self.cfg.loss_b;
        let t = &mut self.truth;
        t.packets_in += 1;
        t.messages_in += h.message_count as u64;
        let range = (h.message_count > 0).then(|| GapRange { from: h.first_seq, to: h.next_seq() - 1 });
        if keep_a { t.packets_a += 1 } else { t.dropped_pkts_a += 1; if let Some(r) = range { push_merged(&mut t.dropped_a, r) } }
        if keep_b { t.packets_b += 1 } else { t.dropped_pkts_b += 1; if let Some(r) = range { push_merged(&mut t.dropped_b, r) } }
        let ts_a = Self::jitter(&mut self.rng_a, capture_ns, self.cfg.delay_a_ns, self.cfg.jitter_ns).max(self.last_ts[0]);
        let ts_b = Self::jitter(&mut self.rng_b, capture_ns, self.cfg.delay_b_ns, self.cfg.jitter_ns).max(self.last_ts[1]);
        self.last_ts = [ts_a, ts_b];
        Route { keep_a, keep_b, ts_a, ts_b }
    }

    pub fn finish(mut self) -> Truth {
        self.truth.dropped_both = intersect(&self.truth.dropped_a, &self.truth.dropped_b);
        self.truth
    }
}

/// Split a pcap file into `out_a` / `out_b` (legacy pcap) and return the truth.
pub fn split_pcap(input: impl AsRef<Path>, out_a: impl AsRef<Path>, out_b: impl AsRef<Path>, cfg: SplitConfig) -> io::Result<Truth> {
    let mut src = PcapFile::open(input)?;
    let mut wa = PcapWriter::create(out_a)?;
    let mut wb = PcapWriter::create(out_b)?;
    let mut sp = Splitter::new(cfg);
    let mut err = None;
    src.for_each(64, &mut |pkt| {
        let Some(udp) = l2::udp_payload_fast(pkt.data) else { return };
        let Ok(seg) = Segment::parse(udp) else { return };
        let r = sp.route(&seg.header, pkt.ts_ns);
        if r.keep_a { if let Err(e) = wa.write(r.ts_a, pkt.data) { err = Some(e) } }
        if r.keep_b { if let Err(e) = wb.write(r.ts_b, pkt.data) { err = Some(e) } }
    })?;
    if let Some(e) = err { return Err(e) }
    wa.finish()?;
    wb.finish()?;
    Ok(sp.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn g(a: u64, b: u64) -> GapRange { GapRange { from: a, to: b } }

    #[test]
    fn intersect_ranges() {
        assert_eq!(intersect(&[g(1, 5), g(10, 20)], &[g(4, 12), g(20, 30)]), vec![g(4, 5), g(10, 12), g(20, 20)]);
        assert_eq!(intersect(&[g(1, 5)], &[g(6, 7)]), vec![]);
    }

    #[test]
    fn deterministic_and_independent() {
        let h = |s: u64| TpHeader { version: 1, message_protocol_id: 0x8004, channel_id: 1, session_id: 1, payload_length: 0, message_count: 2, stream_offset: 0, first_seq: s, send_time: 0 };
        let cfg = SplitConfig { loss_a: 0.3, loss_b: 0.3, seed: 7, delay_a_ns: 0, delay_b_ns: 1000, jitter_ns: 0 };
        let mut s1 = Splitter::new(cfg);
        let mut s2 = Splitter::new(cfg);
        let r1: Vec<_> = (0..200).map(|i| s1.route(&h(1 + 2 * i), i * 10)).collect();
        let r2: Vec<_> = (0..200).map(|i| s2.route(&h(1 + 2 * i), i * 10)).collect();
        assert_eq!(r1, r2, "seeded ⇒ reproducible");
        assert!(r1.iter().any(|r| r.keep_a != r.keep_b), "sites drop independently");
        assert!(r1.iter().all(|r| r.ts_b == r.ts_a + 1000));
        let t = s1.finish();
        assert_eq!(t.dropped_pkts_a + t.packets_a, 200);
        assert_eq!(t.dropped_a.iter().map(|g| g.len()).sum::<u64>(), t.dropped_pkts_a * 2);
        assert_eq!(t.dropped_both, intersect(&t.dropped_a, &t.dropped_b));
    }
}
