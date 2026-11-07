# Storage: measurements and 5 TB/day design

`store`: zstd block compression, JSON index in the footer, seek by `(session, seq)` and by capture time. Measured on the 2019-12-24 IEX DEEP half-day (4.74 M messages, single writer on the arbiter thread, M4):

| zstd level | on disk | vs. raw records | vs. source pcapng (695 MB) | write rate |
|---:|---:|---:|---:|---:|
| 1 | 94.2 MB | 2.04× | 7.4× | 220 MB/s raw, 5.4 Mmsg/s (pipeline wall) |
| 3 | 88.8 MB | 2.16× | 7.8× | 206 MB/s |
| 6 | 84.4 MB | 2.28× | 8.2× | 107 MB/s |

Range read: 101 of 4.7 M records in 0.9 ms (2 blocks).

## 5 TB/day

5 TB/day ≈ 58 MB/s average; open/close bursts 10–20× → design ingest ≥ 1 GB/s.

**Partitioning**: one file per (feed, session/channel, 5–15 min window), 1–5 GB raw. Sequence numbers are per session → each partition self-describing (`first_seq..last_seq` in name/index), no cross-file state; compression, verification, replication, expiry per file in parallel.

**Blocks**: 4 K messages (~100–200 KB raw) = seek granularity; delta-coded seq/capture/send timestamps before zstd (~20 B/msg vs ~40). Expected 2–3× on records, 7–8× on the wire capture at zstd-1/3; a per-feed trained dictionary adds 20–40 % on small blocks.

**Write path**: one writer thread per partition behind an SPSC ring (today compression runs on the arbiter thread). Sequential appends, `O_DIRECT`/`fdatasync` per block; one NVMe sustains 1–3 GB/s sequential.

**Retention**

| tier | keep | where | purpose |
|---|---|---|---|
| hot: merged `.tri` | 7–30 days | local NVMe | replay, T+1 analysis at seek granularity |
| warm: same, re-compressed higher off-peak | 3–12 months | object store / HDD | look-back, research |
| cold: raw A- and B-side pcaps | per regulation (5–7 y) | object store, archive class | the raw sides are the evidence; merged is derived |

5 TB/day raw → ~700 GB/day merged+compressed at 7×; 30-day hot tier ≈ 20 TB.

**Integrity**: index carries per-block byte lengths; per-block xxhash/CRC next to `clen` not implemented. Residual gaps recorded in the index (missing at source vs. lost by the store).

**Queries**: `(session, seq)` for replay/reconciliation, capture time for point-in-time. Symbol-level access = secondary index or columnar re-encode off the hot path.
