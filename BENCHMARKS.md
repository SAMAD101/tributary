# Benchmarks

All numbers are from one recorded run on the machine below, by the commands given
in each section. Only [§8](#8-projection-to-60-mpps) projects; everything else is
measured.

## Machine and data

|           |                                                                       |
| --------- | --------------------------------------------------------------------- |
| Host      | MacBook Air, Apple M4 (4 performance + 6 efficiency cores), 16 GB     |
| OS        | macOS (Darwin 25.6.0, arm64)                                          |
| Toolchain | rustc 1.97.1, `--release` (thin LTO, `codegen-units = 1`)             |
| Pinning   | none — macOS ignores `core_affinity`                                  |

- **Fixture** — DEEP 1.0, 2019-12-24 09:30 ET: 2,000 packets, 10,520 messages,
  0.43 MB inflated (213 B per pcap record), 5.26 messages/packet.
- **DEEP full day** — 2019-12-24: 4,649,894 packets, 4,744,663 messages, 695 MB
  inflated pcapng (537 MB of frame bytes), 172 MB gzipped, 1.02 messages/packet.
- **TOPS full day** — 2019-12-24: 4,236,621 packets, 4,290,872 messages, 677 MB
  inflated, 161 MB gzipped.

## 1. Parse → decode → gap-detect, in-memory replay

`tributary replay fixtures/deep_20191224_1430.pcap.gz --cores N --repeat 30000`

60,000,000 packets per worker (2,000 × 30,000) = 315.6 M messages. Each worker is
independent: same data, no sharing.

|           N cores | Mpps | Mmsg/s | Gbit/s (payload) |   wall |
| ----------------: | ---: | -----: | ---------------: | -----: |
|                 1 | 50.4 |    265 |             79.4 | 1.19 s |
|                 2 | 97.4 |    512 |              154 | 1.23 s |
|                 4 |  192 |  1,012 |              304 | 1.25 s |
| 8 (4 performance + 4 efficiency) | 266 | 1,398 | 419 | 1.81 s |

19.8 ns/packet on one performance core.

## 2. Same loop, full day resident in memory

`tributary replay data/20191224_IEXTP1_DEEP1.0.pcap.gz --cores N --repeat 1`

537 MB of frame bytes, DRAM-streamed.

| cores | Mpps | Mmsg/s |
| ----: | ---: | -----: |
|     1 | 35.7 |   36.5 |
|     4 |  234 |    239 |

28.0 ns/packet on one core.

## 3. Streaming ingest from gzipped pcap/pcapng, one core

`tributary gaps FILE`, best of 4. Inflate + parse + gap-detect; the inflater is
the bound. Full-day files are pcapng as published by IEX, fixtures are classic
pcap.

| file                  | packets   | messages  | gz → inflated  |   wall | Mpps | inflated MB/s | gaps |
| --------------------- | --------: | --------: | -------------: | -----: | ---: | ------------: | ---: |
| DEEP 1.0 full day     | 4,649,894 | 4,744,663 | 172 → 695 MB   | 1.00 s | 4.63 |           695 |    0 |
| TOPS 1.6 full day     | 4,236,621 | 4,290,872 | 161 → 677 MB   | 0.98 s | 4.34 |           694 |    0 |
| DEEP fixture          | 2,000     | 10,520    | 0.10 → 0.43 MB |  211 µs |  9.5 |             — |    0 |
| TOPS fixture          | 2,000     | 9,340     | 0.10 → 0.61 MB |  176 µs | 11.3 |             — |    0 |

## 4. A/B arbiter: two reader threads → SPSC rings → one arbiter core

`tributary replay FIXTURE --arbiter --repeat 300 --rate R`

In-memory split, 1% independent loss per site, site B +200 µs ± 20 µs, reorder
window 64 K messages. Latency = ring enqueue → message emitted, sampled 1/16.

| rate per site | in (Mpps, A+B) | emitted Mmsg/s | latency p50 |    p90 |    p99 |
| ------------- | -------------: | -------------: | ----------: | -----: | -----: |
| max           |           13.3 |           35.3 |  — (queueing) |      |      |
| 250 k         |           0.50 |           1.33 |      0.67 µs | 1.5 µs | 2.2 ms |
| 500 k         |           1.00 |           2.66 |      0.63 µs | 1.5 µs | 126 µs |
| 1 M           |           2.00 |           5.32 |      0.71 µs |  32 µs | 161 µs |
| 2 M           |           4.00 |           10.6 |       5.1 µs |  59 µs | 129 µs |

p99 and above is scheduler preemption of spinning threads: no CPU isolation, no
pinning on macOS. File-based path (`absplit` → `arbiter`, full day, 9.1 M packets
from disk): 1.01 s, residual == truth.

## 5. Micro-benchmarks

`cargo bench -p tp-parse` (criterion, DEEP fixture).

| benchmark                              |   per element | throughput |
| -------------------------------------- | ------------: | ---------: |
| Ethernet → IPv4 → UDP, `etherparse`     | 13.1 ns/frame |   76.5 M/s |
| same, fixed-shape fast path            | 1.26 ns/frame |    796 M/s |
| IEX-TP header parse + iterate messages |  9.6 ns/frame |    104 M/s |
| full message decode, all types         |    4.8 ns/msg |    206 M/s |
| peek type + timestamp                  |   0.52 ns/msg |   1.93 G/s |
| L2 + TP + decode every message         | 23.6 ns/frame |   42.4 M/s |

## 6. Storage

`tributary arbiter a.pcap b.pcap --out merged.tri --zstd-level L`

Full day, 4,742,744 messages, compression on the arbiter thread.

| zstd level | on disk | vs. raw records (192 MB) | vs. source pcapng (695 MB) | pipeline wall (2 × 599 MB pcap in + arbitrate + write) |
| ---------: | ------: | -----------------------: | -------------------------: | -----------------------------------------------------: |
|          1 | 94.2 MB |                    2.04× |                       7.4× |                     0.87 s → 220 MB/s raw, 5.4 Mmsg/s |
|          3 | 88.8 MB |                    2.16× |                       7.8× |                                                 0.93 s |
|          6 | 84.4 MB |                    2.28× |                       8.2× |                                                 1.80 s |

Range read: 101 records (seq 2,000,000–2,000,100 of 4.74 M) in 0.87 ms — index
lookup plus two decompressed blocks.

## 7. Not covered

- No NIC. Frames come from cache or DRAM: no DMA'd-frame cache misses, no AF_XDP
  ring operations, no fill-ring refill.
- Not 60 Mpps. The 10 GbE test box caps at 14.88 Mpps.
- Tail latency on macOS is dominated by the scheduler, not the software.
- No PTP or hardware timestamps. All times in these runs are IEX send times plus
  synthetic A/B delay.

## 8. Projection to 60 Mpps

Minimum frame on the wire = 64 + 8 + 12 = 84 B = 672 bit.

- 10 GbE: 10e9 / 672 = 14.88 Mpps.
- 60 Mpps × 672 bit = 40.3 Gbit/s → 40/50/100 GbE, or 4 × 10G / 2 × 25G with RSS.
- 60 Mpps at 170 B on wire (1,360 bit) = 81.6 Gbit/s → 100 GbE.

Per-core budget, 60 Mpps / N:

| cores | pps/core | ns/packet |
| ----: | -------: | --------: |
|     4 |   15.0 M |      66.7 |
|     6 |   10.0 M |       100 |
|     8 |    7.5 M |       133 |
|    12 |    5.0 M |       200 |
|    16 |   3.75 M |       267 |

Measured memory-resident: 19.8–28.0 ns/packet including decode and sequence
tracking. Unmeasured: AF_XDP per-packet cost (RX descriptor, one cache-line miss
on the DMA'd header, fill-ring return, PCIe). Published AF_XDP zero-copy rxdrop
figures are 15–25 Mpps/core on recent x86 (i40e/ice/mlx5); assume 5–10 Mpps/core
for capture + parse + gap-detect on a server core.

That gives 6–12 RSS queues and pinned cores, plus 1–2 arbiter/output cores and 1
housekeeping core. RSS is symmetric on the UDP 4-tuple, so one session maps to
one queue with no cross-core session state, and A and B of a session go to the
same arbiter. The arbiter handles 13 Mpps in / 35 Mmsg/s per core here and can be
sharded by session.

UMEM sizing: 100 µs stall × 60 Mpps / 8 queues = 750 frames per queue, so
4,096-frame UMEMs (8 MiB at 2 KiB frames). Storage: 60 Mpps × 150 B ≈ 9 GB/s raw
before compression ([RETENTION.md](crates/store/RETENTION.md)).

Next step: `tributary live --backend afxdp` per queue on a 10G NIC; the wire
ceiling is expected to be hit first.

## Re-check, 2026-11-07

Same host, macOS 27.0.1, rustc 1.98.1:

- `cargo test --workspace`: 32 tests pass.
- `tributary gaps` on both full-day files: 0 gaps.
- `tributary arbiter out/fullday/{a,b}.pcap --truth`: PASS, 4,742,744 emitted,
  1,919 residual.
- `tributary store info out/fullday/merged.tri`: 84.4 MB, 2.28×.
- Full-day DRAM replay: 44.7 Mpps on one core vs 35.7 in §2, so §2 is
  conservative.
- Criterion: fast path, TP parse, decode, peek and full-frame costs within 6% of
  §5; `etherparse` measured 14.4 ns/frame vs 13.1.
