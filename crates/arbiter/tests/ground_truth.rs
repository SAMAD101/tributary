//! THE ground-truth test. `absplit` knows exactly which packets each site
//! dropped, so we can prove the arbiter's output is:
//!   * strictly ordered, duplicate-free, byte-identical to the original,
//!   * gap-free wherever at least one site had the packet,
//!   * and its residual gaps are exactly dropped_A ∩ dropped_B.
//!
//! Run single-threaded with timestamp-ordered interleaving (deterministic) and
//! through the concurrent two-thread pipeline on real pcap files.

use std::collections::BTreeMap;
use std::time::Duration;

use absplit::{intersect, SplitConfig, Splitter, Truth};
use arbiter::{pipeline, subtract, Arbiter, Config, Emit, Site};
use capture::{CaptureSource, PcapFile};
use gapdetect::GapRange;
use tp_parse::{l2, Segment};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/deep_20191224_1430.pcap.gz");

struct Pkt { ts: u64, frame: Vec<u8> }

fn load() -> Vec<Pkt> {
    let mut v = Vec::new();
    PcapFile::open(FIXTURE).unwrap().for_each(64, &mut |p| v.push(Pkt { ts: p.ts_ns, frame: p.data.to_vec() })).unwrap();
    v
}

/// seq → original message bytes, from the clean stream.
fn originals(pkts: &[Pkt]) -> BTreeMap<u64, Vec<u8>> {
    let mut m = BTreeMap::new();
    for p in pkts {
        let seg = Segment::parse(l2::udp_payload_fast(&p.frame).unwrap()).unwrap();
        for r in seg.messages() { let (seq, b) = r.unwrap(); m.insert(seq, b.to_vec()); }
    }
    m
}

fn clip(ranges: &[GapRange], lo: u64, hi: u64) -> Vec<GapRange> {
    ranges.iter().filter_map(|g| {
        let (f, t) = (g.from.max(lo), g.to.min(hi));
        (f <= t).then_some(GapRange { from: f, to: t })
    }).collect()
}

fn check(truth: &Truth, emitted: &[(u64, Site, Vec<u8>)], residual: &[GapRange], report: &arbiter::Report, orig: &BTreeMap<u64, Vec<u8>>) {
    let s = &report.sessions[0];
    let (lo, hi) = (emitted.first().unwrap().0, s.next_seq - 1);
    // 1. strictly increasing, no dups, byte-identical
    for w in emitted.windows(2) { assert!(w[0].0 < w[1].0, "order/dup at {}", w[1].0); }
    for (seq, _, body) in emitted { assert_eq!(&orig[seq], body, "seq {seq} bytes"); }
    // 2. residual gaps == A ∩ B (within the observed span — a loss at the very
    //    end of the file that BOTH sites suffered is invisible to everyone)
    let both = clip(&truth.dropped_both, lo, hi);
    assert_eq!(residual, &both[..], "residual gaps must equal dropped_A ∩ dropped_B");
    assert_eq!(s.residual_gaps, both);
    // 3. everything else was emitted: |emitted| + |residual| = span
    let missing: u64 = both.iter().map(|g| g.len()).sum();
    assert_eq!(emitted.len() as u64 + missing, hi - lo + 1);
    // 4. per-site loss seen by the arbiter matches the truth (within what that
    //    site's own sequence tracker could observe), and recovery bookkeeping is right
    let span = |r: &gapdetect::SessionReport| (r.first_seq.max(lo), (r.expected_next - 1).min(hi));
    let (alo, ahi) = span(&report.site_a[0]);
    let (blo, bhi) = span(&report.site_b[0]);
    assert_eq!(s.site_a_gaps, clip(&truth.dropped_a, alo, ahi));
    assert_eq!(s.site_b_gaps, clip(&truth.dropped_b, blo, bhi));
    assert_eq!(s.recovered_from_b, subtract(&clip(&truth.dropped_a, alo, ahi), &both));
    assert_eq!(s.recovered_from_a, subtract(&clip(&truth.dropped_b, blo, bhi), &both));
    let wins: u64 = s.site.iter().map(|x| x.wins + x.wins_from_buffer).sum();
    assert_eq!(wins, emitted.len() as u64);
    assert_eq!(s.emitted, emitted.len() as u64);
}

type Emitted = Vec<(u64, Site, Vec<u8>)>;

fn run_single(pkts: &[Pkt], cfg: SplitConfig, window: usize) -> (Truth, Emitted, Vec<GapRange>, arbiter::Report) {
    let mut sp = Splitter::new(cfg);
    let mut events: Vec<(u64, Site, usize)> = Vec::new();
    for (i, p) in pkts.iter().enumerate() {
        let seg = Segment::parse(l2::udp_payload_fast(&p.frame).unwrap()).unwrap();
        let r = sp.route(&seg.header, p.ts);
        if r.keep_a { events.push((r.ts_a, Site::A, i)); }
        if r.keep_b { events.push((r.ts_b, Site::B, i)); }
    }
    events.sort_by_key(|e| e.0); // stable: A before B on ties
    let truth = sp.finish();
    let mut arb = Arbiter::new(Config { window });
    let (mut emitted, mut gaps) = (Vec::new(), Vec::new());
    let mut out = |e: Emit<'_>| match e {
        Emit::Msg(m) => emitted.push((m.seq, m.site, m.body.to_vec())),
        Emit::Gap { from, to, .. } => match gaps.last_mut() {
            Some(l @ GapRange { .. }) if l.to + 1 == from => l.to = to,
            _ => gaps.push(GapRange { from, to }),
        },
    };
    for (ts, site, i) in events {
        let seg = Segment::parse(l2::udp_payload_fast(&pkts[i].frame).unwrap()).unwrap();
        arb.push(site, &seg, ts, &mut out);
    }
    arb.finish(&mut out);
    (truth, emitted, gaps, arb.report())
}

#[test]
fn arbiter_output_matches_ground_truth() {
    let pkts = load();
    let orig = originals(&pkts);
    let cases = [
        SplitConfig { loss_a: 0.01, loss_b: 0.01, seed: 1, ..Default::default() },
        SplitConfig { loss_a: 0.05, loss_b: 0.05, seed: 2, ..Default::default() },
        SplitConfig { loss_a: 0.20, loss_b: 0.20, seed: 3, ..Default::default() },
        SplitConfig { loss_a: 0.50, loss_b: 0.10, seed: 4, delay_b_ns: 2_000_000, jitter_ns: 500_000, ..Default::default() },
        SplitConfig { loss_a: 0.00, loss_b: 0.30, seed: 5, delay_a_ns: 1_000_000, delay_b_ns: 0, jitter_ns: 0 },
        SplitConfig { loss_a: 0.30, loss_b: 0.30, seed: 6, delay_a_ns: 0, delay_b_ns: 0, jitter_ns: 3_000_000 },
    ];
    for cfg in cases {
        for seed in [cfg.seed, cfg.seed + 100, cfg.seed + 200] {
            let cfg = SplitConfig { seed, ..cfg };
            let (truth, emitted, gaps, report) = run_single(&pkts, cfg, 1 << 16);
            assert!(truth.dropped_pkts_a + truth.dropped_pkts_b > 0 || cfg.loss_a + cfg.loss_b == 0.0);
            check(&truth, &emitted, &gaps, &report, &orig);
            let s = &report.sessions[0];
            eprintln!("loss {:.2}/{:.2} seed {seed}: in {} emitted {} residual {} (A lost {}, B lost {}, both {}) winsA {} winsB {}",
                cfg.loss_a, cfg.loss_b, truth.messages_in, s.emitted, s.residual_missing,
                truth.dropped_a.iter().map(|g| g.len()).sum::<u64>(), truth.dropped_b.iter().map(|g| g.len()).sum::<u64>(),
                truth.dropped_both.iter().map(|g| g.len()).sum::<u64>(),
                s.site[0].wins + s.site[0].wins_from_buffer, s.site[1].wins + s.site[1].wins_from_buffer);
        }
    }
}

#[test]
fn intersection_sanity() {
    let pkts = load();
    let (truth, ..) = run_single(&pkts, SplitConfig { loss_a: 0.3, loss_b: 0.3, seed: 9, ..Default::default() }, 1 << 16);
    assert_eq!(truth.dropped_both, intersect(&truth.dropped_a, &truth.dropped_b));
    assert!(!truth.dropped_both.is_empty(), "30%/30% must produce some double drops");
}

#[test]
fn concurrent_pipeline_on_pcap_files_matches_ground_truth() {
    let pkts = load();
    let orig = originals(&pkts);
    let dir = std::env::temp_dir().join(format!("tributary-arb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (a, b) = (dir.join("a.pcap"), dir.join("b.pcap"));
    for seed in [11u64, 12, 13] {
        let cfg = SplitConfig { loss_a: 0.1, loss_b: 0.1, seed, ..Default::default() };
        let truth = absplit::split_pcap(FIXTURE, &a, &b, cfg).unwrap();
        let (mut emitted, mut gaps) = (Vec::new(), Vec::new());
        let (report, stats) = pipeline::run_dual(
            PcapFile::open(&a).unwrap(), PcapFile::open(&b).unwrap(), Config::default(), 4096, Duration::from_micros(20),
            |e, _enq| match e {
                Emit::Msg(m) => emitted.push((m.seq, m.site, m.body.to_vec())),
                Emit::Gap { from, to, .. } => match gaps.last_mut() {
                    Some(l @ GapRange { .. }) if l.to + 1 == from => l.to = to,
                    _ => gaps.push(GapRange { from, to }),
                },
            },
        ).unwrap();
        assert_eq!(stats.packets, [truth.packets_a, truth.packets_b]);
        check(&truth, &emitted, &gaps, &report, &orig);
    }
    std::fs::remove_dir_all(&dir).ok();
}
