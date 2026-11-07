//! Ground-truth tests on the real IEX fixture: clean file ⇒ zero gaps;
//! deliberately corrupted copies ⇒ exactly the gaps we introduced.

use capture::{CaptureSource, PcapFile};
use gapdetect::{Event, GapDetector, GapRange};
use tp_parse::{l2, Segment, TpHeader};

fn load() -> Vec<(u64, TpHeader)> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/deep_20191224_1430.pcap.gz");
    let mut src = PcapFile::open(p).unwrap();
    let mut v = Vec::new();
    src.for_each(64, &mut |pkt| {
        let seg = Segment::parse(l2::udp_payload_fast(pkt.data).unwrap()).unwrap();
        v.push((pkt.ts_ns, seg.header));
    }).unwrap();
    v
}

#[test]
fn clean_fixture_has_no_gaps() {
    let hdrs = load();
    let mut d = GapDetector::new();
    for (ts, h) in &hdrs {
        assert!(matches!(d.observe(h, *ts), Event::Start | Event::InOrder));
    }
    let r = d.report();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].gap_count, 0);
    assert_eq!(r[0].missing_msgs, 0);
    assert_eq!(r[0].duplicate_segments, 0);
    assert_eq!(r[0].messages, 10520); // matches reference golden
    assert_eq!(r[0].first_seq, 57244);
    assert_eq!(r[0].last_seq, 67763);
    assert!(r[0].capture_span_ns() > 0);
}

#[test]
fn removed_segments_are_reported_exactly() {
    let hdrs = load();
    // Drop segment indices 10, 11 (adjacent → one merged gap), 500, and every 97th after 1000.
    let mut drop = vec![10usize, 11, 500];
    drop.extend((1000..hdrs.len()).step_by(97));
    // expected gaps: contiguous seq ranges of the dropped, message-bearing segments
    let mut expected: Vec<GapRange> = Vec::new();
    for &i in &drop {
        let h = &hdrs[i].1;
        if h.message_count == 0 { continue; } // dropping a heartbeat loses no messages
        let g = GapRange { from: h.first_seq, to: h.next_seq() - 1 };
        match expected.last_mut() {
            Some(last) if last.to + 1 == g.from => last.to = g.to,
            _ => expected.push(g),
        }
    }
    let mut d = GapDetector::new();
    for (i, (ts, h)) in hdrs.iter().enumerate() {
        if drop.contains(&i) { continue; }
        d.observe(h, *ts);
    }
    let r = &d.report()[0];
    assert_eq!(r.gaps, expected);
    assert_eq!(r.missing_msgs, expected.iter().map(|g| g.len()).sum::<u64>());
    assert_eq!(r.messages + r.missing_msgs, 10520);
}

#[test]
fn duplicated_and_swapped_segments() {
    let hdrs = load();
    let mut d = GapDetector::new();
    let mut dup_msgs = 0;
    for (i, (ts, h)) in hdrs.iter().enumerate() {
        // swap 300 <-> 301 (both message-bearing in this fixture) and duplicate every 50th
        let (ts, h) = match i { 300 => (&hdrs[301].0, &hdrs[301].1), 301 => (&hdrs[300].0, &hdrs[300].1), _ => (ts, h) };
        d.observe(h, *ts);
        if i % 50 == 0 && h.message_count > 0 {
            assert_eq!(d.observe(h, *ts), Event::Duplicate);
            dup_msgs += h.message_count as u64;
        }
    }
    let r = &d.report()[0];
    assert_eq!(r.gaps, vec![], "swap must be healed as a reorder");
    assert_eq!(r.reordered_segments, 1);
    assert_eq!(r.duplicate_msgs, dup_msgs);
    assert_eq!(r.messages, 10520);
}
