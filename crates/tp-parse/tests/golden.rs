//! Parser-equivalence test: tp-parse vs. the reference Python parser
//! (rob-blackbourn/iex_parser) on the same fixture. The golden JSON is produced
//! by `scripts/reference_golden.py` and committed next to the fixture.

use std::collections::BTreeMap;
use std::path::PathBuf;

use capture::{CaptureSource, PcapFile};
use serde::Deserialize;
use tp_parse::{decode, l2, Message, Segment};

#[derive(Deserialize)]
struct Golden {
    protocol: String,
    message_protocol_id: u16,
    packets: u64,
    messages: u64,
    by_type: BTreeMap<String, u64>,
    first_seq: u64,
    last_seq: u64,
    seq_contiguous: bool,
    fnv1a64: u64,
    sample: Vec<Sample>,
}

#[derive(Deserialize)]
struct Sample {
    seq: u64,
    #[serde(rename = "type")]
    kind: String,
    symbol: String,
    ts_s: i64,
    size: Option<u32>,
    price: Option<i64>,
    trade_id: Option<i64>,
    flags: Option<u8>,
    bid_size: Option<u32>,
    bid_price: Option<i64>,
    ask_size: Option<u32>,
    ask_price: Option<i64>,
    side: Option<String>,
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

fn fnv1a64(h: &mut u64, data: &[u8]) {
    for &b in data {
        *h ^= b as u64;
        *h = h.wrapping_mul(0x100000001b3);
    }
}

fn check(pcap: &str, golden: &str) {
    let g: Golden = serde_json::from_reader(std::fs::File::open(fixture(golden)).unwrap()).unwrap();
    let mut src = PcapFile::open(fixture(pcap)).unwrap();

    let mut packets = 0u64;
    let mut messages = 0u64;
    let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
    let mut first_seq = None;
    let mut last_seq = 0;
    let mut expected: Option<u64> = None;
    let mut contiguous = true;
    let mut h = 0xcbf29ce484222325u64;
    let mut sample_i = 0usize;
    let mut proto = 0u16;

    src.for_each(64, &mut |pkt| {
        let udp = l2::udp_payload_fast(pkt.data).expect("udp");
        let seg = Segment::parse(udp).expect("iex-tp");
        proto = seg.header.message_protocol_id;
        packets += 1;
        if let Some(e) = expected {
            if seg.header.first_seq != e {
                contiguous = false;
            }
        }
        expected = Some(seg.header.next_seq());
        for r in seg.messages() {
            let (seq, body) = r.unwrap();
            let m = decode(body).unwrap();
            messages += 1;
            first_seq.get_or_insert(seq);
            last_seq = seq;
            *by_type.entry((m.kind() as char).to_string()).or_default() += 1;
            let sym = m.symbol().map(|s| s.as_str().to_string()).unwrap_or_default();
            let (size, price) = match m {
                Message::TradeReport(t) | Message::TradeBreak(t) => (t.size, t.price),
                Message::PriceLevelUpdate(p) => (p.size, p.price),
                Message::QuoteUpdate(q) => (q.bid_size, q.bid_price),
                Message::OfficialPrice(o) => (0, o.price),
                _ => (0, 0),
            };
            fnv1a64(&mut h, format!("{seq}|{}|{sym}|{size}|{price}\n", m.kind() as char).as_bytes());

            if sample_i < g.sample.len() {
                let s = &g.sample[sample_i];
                sample_i += 1;
                assert_eq!(seq, s.seq);
                assert_eq!(m.kind() as char, s.kind.chars().next().unwrap());
                assert_eq!(sym, s.symbol);
                assert_eq!(m.timestamp().div_euclid(1_000_000_000), s.ts_s, "seq {seq}");
                match m {
                    Message::TradeReport(t) | Message::TradeBreak(t) => {
                        assert_eq!(Some(t.size), s.size);
                        assert_eq!(Some(t.price), s.price);
                        assert_eq!(Some(t.trade_id), s.trade_id);
                        assert_eq!(Some(t.sale_condition_flags), s.flags);
                    }
                    Message::PriceLevelUpdate(p) => {
                        assert_eq!(Some(p.size), s.size);
                        assert_eq!(Some(p.price), s.price);
                        assert_eq!(Some(p.event_flags), s.flags);
                        assert_eq!(s.side.as_deref(), Some(if p.buy { "B" } else { "S" }));
                    }
                    Message::QuoteUpdate(q) => {
                        assert_eq!(Some(q.bid_size), s.bid_size);
                        assert_eq!(Some(q.bid_price), s.bid_price);
                        assert_eq!(Some(q.ask_size), s.ask_size);
                        assert_eq!(Some(q.ask_price), s.ask_price);
                        assert_eq!(Some(q.flags), s.flags);
                    }
                    Message::OfficialPrice(o) => assert_eq!(Some(o.price), s.price),
                    _ => {}
                }
            }
        }
    })
    .unwrap();

    assert_eq!(proto, g.message_protocol_id, "{}", g.protocol);
    assert_eq!(packets, g.packets);
    assert_eq!(messages, g.messages);
    assert_eq!(by_type, g.by_type);
    assert_eq!(first_seq, Some(g.first_seq));
    assert_eq!(last_seq, g.last_seq);
    assert_eq!(contiguous, g.seq_contiguous);
    assert_eq!(h, g.fnv1a64, "fnv over (seq,type,symbol,size,price) of every message");
    assert_eq!(sample_i, g.sample.len());
}

#[test]
fn deep_1_0_matches_reference_parser() {
    check("deep_20191224_1430.pcap.gz", "deep_20191224_1430.golden.json");
}

#[test]
fn tops_1_6_matches_reference_parser() {
    check("tops_20191224_1430.pcap.gz", "tops_20191224_1430.golden.json");
}
