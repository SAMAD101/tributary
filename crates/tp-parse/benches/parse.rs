//! Micro-benchmarks: per-frame L2→UDP walk, IEX-TP segment parse, per-message decode.
//! Data: the committed DEEP fixture (2000 real frames, 10520 messages).

use capture::{CaptureSource, PcapFile};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::hint::black_box;
use tp_parse::{l2, msg, Segment};

fn frames() -> Vec<Vec<u8>> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/deep_20191224_1430.pcap.gz");
    let mut v = Vec::new();
    PcapFile::open(p).unwrap().for_each(64, &mut |pk| v.push(pk.data.to_vec())).unwrap();
    v
}

fn bench(c: &mut Criterion) {
    let frames = frames();
    let msgs: Vec<Vec<u8>> = frames.iter().flat_map(|f| {
        Segment::parse(l2::udp_payload_fast(f).unwrap()).unwrap().messages().map(|m| m.unwrap().1.to_vec()).collect::<Vec<_>>()
    }).collect();
    let n_msgs = msgs.len() as u64;

    let mut g = c.benchmark_group("l2");
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.bench_function("etherparse udp_payload (2000 frames)", |b| b.iter(|| for f in &frames { black_box(l2::udp_payload(black_box(f))); }));
    g.bench_function("fast-path udp_payload_fast (2000 frames)", |b| b.iter(|| for f in &frames { black_box(l2::udp_payload_fast(black_box(f))); }));
    g.finish();

    let mut g = c.benchmark_group("iex-tp");
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.bench_function("Segment::parse + iterate messages (2000 frames)", |b| b.iter(|| {
        let mut acc = 0u64;
        for f in &frames {
            let s = Segment::parse(l2::udp_payload_fast(f).unwrap()).unwrap();
            for m in s.messages() { acc = acc.wrapping_add(m.unwrap().0); }
        }
        black_box(acc)
    }));
    g.finish();

    let mut g = c.benchmark_group("decode");
    g.throughput(Throughput::Elements(n_msgs));
    g.bench_function("msg::decode all (10520 msgs)", |b| b.iter(|| {
        let mut acc = 0i64;
        for m in &msgs { acc = acc.wrapping_add(msg::decode(black_box(m)).unwrap().timestamp()); }
        black_box(acc)
    }));
    g.bench_function("msg::peek_kind_ts all (10520 msgs)", |b| b.iter(|| {
        let mut acc = 0i64;
        for m in &msgs { acc = acc.wrapping_add(msg::peek_kind_ts(black_box(m)).unwrap().1); }
        black_box(acc)
    }));
    g.finish();

    // full per-frame pipeline cost: L2 → TP → decode every message
    let mut g = c.benchmark_group("frame-pipeline");
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.bench_function("l2+tp+decode (2000 frames)", |b| b.iter_batched(|| (), |_| {
        let mut acc = 0i64;
        for f in &frames {
            let s = Segment::parse(l2::udp_payload_fast(f).unwrap()).unwrap();
            for m in s.messages() { acc = acc.wrapping_add(msg::decode(m.unwrap().1).unwrap().timestamp()); }
        }
        black_box(acc)
    }, BatchSize::SmallInput));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
