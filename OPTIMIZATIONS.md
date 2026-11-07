# Optimizations

Every optimization in this codebase serves one number: **the per-packet software
budget**. At the target of 60 Mpps across 8 cores, one core has ~133 ns per
packet. The whole parse → decode → gap-detect path is measured at ~21–28 ns per
packet, so the budget only fits if *nothing* else per packet is allowed — no
allocation, no lock, no syscall, no cache-miss chain.

This file lists each optimization, *why* it matters, where it lives, and its
measured effect where one exists. Hot path = the per-packet loop that runs on
every captured frame.

---

## 1. Zero-copy: borrow the bytes, never memcpy them

**What.** The `CaptureSource` contract hands out `Packet { data: &[u8] }` — a
borrowed slice into the backend's own buffer — instead of an owned `Vec<u8>`.

```rust
pub trait CaptureSource {
    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(Packet<'_>)) -> io::Result<Option<usize>>;
}
```

**Why.** Copying a 150 B frame 60 M times/s is ~9 GB/s of memcpy doing nothing
useful. Every parse step (`Segment::parse`, `messages()`, `decode`) also returns
borrowed slices, so a message body is *pointed at*, never duplicated.

**Where.** `crates/capture/src/lib.rs:26` (`Packet`), `crates/tp-parse/src/lib.rs`
(`Segment<'a>`, `MessageIter<'a>`, `Message` body slices).

**The one allowed copy.** In the two-thread pipeline a frame is copied *once*
into a fixed 1,536 B ring slot (`crates/arbiter/src/pipeline.rs:66`). That copy
is unavoidable with a file backend (the reader reuses its buffer), and it is
deliberately *not* on the parse path. On AF_XDP you would pass UMEM frame indices
instead and drop even this copy (noted in `pipeline.rs:5`).

---

## 2. Fixed-shape L2 fast path (1.27 ns vs 14.4 ns)

**What.** Instead of running a general Ethernet/IPv4/UDP parser on every frame,
test four bytes and, if they match the exact frame shape IEX sends, slice the
UDP payload directly:

```rust
pub fn udp_payload_fast(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() >= ETH_IPV4_UDP_HEADERS
        && frame[12] == 0x08 && frame[13] == 0x00 // EtherType 0x0800 = IPv4
        && frame[14] == 0x45                       // version 4, IHL 5 (no options)
        && frame[23] == 17                         // IP protocol 17 = UDP
    {
        // ... UDP length sanity, then &frame[42 .. 42+udp_len]
    }
    udp_payload(frame) // fall back to the general parser
}
```

**Why.** The general parser (`etherparse::SlicedPacket`) must walk every header,
handle options, IPv6, VLAN, fragmentation, etc. — 13.1 ns/frame. The fast path
is 4 byte comparisons and a slice — 1.26 ns/frame, an ~11× win. At 60 Mpps that
is ~0.79 s/s of saved latency: the difference between keeping up and not.

**Where.** `crates/tp-parse/src/l2.rs:23`. Bench: `crates/tp-parse/benches/parse.rs`.

**Trade-off.** If the shape doesn't match, it falls through to `udp_payload`,
so correctness is preserved for anything unusual.

---

## 3. Packed-struct unaligned read: one bounds check, one load

**What.** Wire formats are declared as `#[repr(C, packed)]` structs and read with
a single `read_unaligned`:

```rust
pub(crate) unsafe fn read_pod<T: Pod>(b: &[u8]) -> Result<T, ParseError> {
    if b.len() < size_of::<T>() { return Err(ParseError::Short { .. }); }
    Ok(unsafe { core::ptr::read_unaligned(b.as_ptr() as *const T) })
}
```

`Pod` is an `unsafe trait` whose contract is "packed, integer-only fields, no
padding, no invariants — any bit pattern is a valid value". Implementors are
guarded by a compile-time size assert:

```rust
const _: () = assert!(size_of::<RawTpHeader>() == TP_HEADER_LEN); // 40
```

**Why.** The alternative — reading `b[0]`, `b[1..3]`, shifting, combining — is
many small operations and many bounds checks per message. This is one check and
one unaligned load for the whole header, then `from_le` into a host struct.
`read_unaligned` is required (not `ptr::read`) because the frame is never
guaranteed aligned; using an aligned read on an unaligned pointer is UB.

**Where.** `crates/tp-parse/src/lib.rs:58` (`Pod`, `read_pod`), `:71`
(`RawTpHeader`), and the `raw!` macro in `crates/tp-parse/src/msg.rs:54` for
every message type.

**Why `unsafe` is sound here.** The length check guarantees the read is in-bounds;
the `Pod` trait guarantees the byte pattern is a valid `T`. This is the parser's
only `unsafe`, and it is the narrowest possible escape hatch (see the SAFETY
comment at `lib.rs:66`).

---

## 4. Zero allocation on the hot path (pre-reserve everything)

**What.** Nothing on the per-packet path calls `Vec::push`/`Box`/`String`. All
capacity is reserved up front.

- `GapDetector` sessions are `Vec::with_capacity(1024)` gap lists created once
  (`crates/gapdetect/src/lib.rs:100`).
- `Arbiter` allocates its whole reorder window — `window` slots × 128 B — when a
  session first appears, not per message (`crates/arbiter/src/lib.rs:134`).
- Ring buffers are sized at startup (`pipeline.rs:92`).
- `PcapFile` allocates its reader buffer at open, not per packet
  (`crates/capture/src/pcapfile.rs:35`).

**Why.** A `malloc`/`free` pair is ~tens of ns and, worse, triggers cache misses
and page faults. At a 133 ns budget, a single allocation per packet would blow
it. Rust does not guarantee "no allocation", so this is a **discipline** encoded
in the crate docs ("No allocation after start-up") and kept by construction:
steady-state loops only index into preallocated structures.

---

## 5. No locks: SPSC rings + thread-local state

**What.** All cross-thread communication is via `rtrb` single-producer/
single-consumer ring buffers; all per-session state is owned by the thread that
uses it.

**Why.** A mutex is a syscall + contention when contended; even an uncontended
`AtomicUsize` `fetch_add` (~5–20 ns) costs more than the whole parse. SPSC rings
need no synchronization in the steady state because only one thread writes a slot
and only one reads it, in a known order. Per-site `GapDetector`s and the
`Arbiter`'s sessions are touched by exactly one thread.

**Where.** `crates/arbiter/src/pipeline.rs:85` (`run_dual` creates two rings);
`crates/metrics/src/lib.rs` (counters are plain `u64`, snapshotted by the
control plane — "no atomics on the hot path").

---

## 6. No syscalls per packet (amortized, and truly zero on AF_XDP)

**What.** The hot loop calls only pure CPU work. Sources amortize kernel traffic:

- **File**: `BufReader`/`MultiGzDecoder` fill a large buffer (1 MB / 4 MB), so a
  `read()` syscall happens per *buffer*, not per packet
  (`crates/capture/src/pcapfile.rs:35`).
- **libpcap**: uses its own 64 MB ring buffer; `poll` drains it without syscalls
  per packet (`crates/capture/src/live.rs:23`).
- **AF_XDP**: reads the RX ring entirely in userspace (`xsk-rs`); the only kernel
  interaction is an occasional `sendto` wakeup, gated by `XDP_USE_NEED_WAKEUP`
  (`crates/capture/src/afxdp.rs:131`). Timestamps use `clock_gettime` via the
  vDSO — userspace, not a real syscall — and only once per *batch*
  (`afxdp.rs:117`).
- **Pacing**: the replay `Pacer` spins on `Instant` instead of `sleep`, which
  would emit a syscall and add ~50 µs of slop (`crates/replay/src/lib.rs:105`).

**Why.** A syscall is ~0.5–1 µs on modern hardware — 5–10× the entire per-packet
budget. "No syscall per packet" is maintained by *construction* of each backend,
not by a runtime check.

---

## 7. Batching (poll ≤ 64)

**What.** Every backend delivers up to `max` packets per `poll`, and the sinks
loop in batches of 64.

**Why.** Amortizes whatever per-call overhead remains (a branch, a function call,
a ring re-check) over 64 packets, and on AF_XDP lets the timestamp + fill-ring
return happen once per batch instead of per frame.

**Where.** `CaptureSource::for_each` (`capture/src/lib.rs:44`), `PcapFile::poll`
loop (`pcapfile.rs:60`), `AfXdp::poll` (`afxdp.rs:130`).

---

## 8. Fixed-size buffers sized to the protocol

**What.** The pipeline ring slot is 1,536 B (max Ethernet frame); the arbiter's
reorder slot is 128 B (IEX messages are ≤ 80 B, the largest being Auction
Information).

```rust
pub const FRAME: usize = 1536;              // crates/arbiter/src/pipeline.rs:20
pub const SLOT: usize = 128;                // crates/arbiter/src/lib.rs:40
```

**Why.** Fixed inline arrays live in the struct, so a slot is a cache-friendly
contiguous region with no indirection; 128 B × 65,536 slots = 8 MiB per session,
predictable. Anything larger than `SLOT` is counted as `oversize` and dropped
rather than heap-allocated (`arbiter/src/lib.rs:190`).

---

## 9. Power-of-two window + bitmask indexing (no `%`)

**What.** The arbiter's reorder window is `1 << 16` slots and is indexed with
`seq & mask` where `mask = window - 1`.

```rust
assert!(cfg.window.is_power_of_two() && cfg.window >= 2);
let slot = &mut s.slots[(seq & s.mask as u64) as usize];   // lib.rs:184
```

**Why.** `x & mask` compiles to one `and` instruction; `x % 65536` compiles to a
division (or several ops) because 65536 is not a small divisor the compiler
special-cases cheaply here. On a per-message path, that difference is measurable.
The power-of-two invariant is enforced in `Arbiter::new` (`lib.rs:122`).

---

## 10. Storage: delta encoding + zstd blocks + a footer index

**What.** `.tri` records are written as uvarint/svarint *deltas* (Δseq, Δcapture,
Δsend) rather than full 8-byte values; 4,096 records are zstd-compressed per
block; a JSON index in the footer maps `(session, seq)` and time ranges to byte
offsets.

**Why.** Adjacent messages differ by "1" in sequence and microseconds in time, so
deltas are one byte instead of eight — ~2× smaller before compression. zstd then
finds the per-symbol repetition. The index lets a range read decompress only the
~2 blocks that overlap instead of the whole file.

**Where.** `crates/store/src/lib.rs` — varints `:79`, block flush `:157`, index
`binary_search` in `blocks_for_seq`/`blocks_for_time` `:226`.

**Measured.** 192 MB raw records → 84.4 MB on disk (2.28×); a 101-record range
read of 4.7 M records in ~1 ms.

---

## 11. Inlining and codegen: `#[inline]`, thin LTO, codegen-units = 1

**What.** Hot functions are marked `#[inline]`/`#[inline(always)]` so they are
inlined *into* the caller's loop rather than called across a function boundary.
The workspace release profile is:

```toml
[profile.release]
lto = "thin"
codegen-units = 1
debug = 1
```

**Why.**
- A function call costs a register spill + jump + return, and — crucially —
  **prevents the caller's context from being optimized together**. Inlining lets
  the compiler see the whole `parse → decode → gap` loop as one body, eliminate
  redundant bounds checks, keep values in registers, and specialize branches.
- `codegen-units = 1` stops the compiler from splitting a crate into parallel
  translation units that can't see each other's bodies, so cross-function
  inlining isn't blocked by CGU boundaries.
- `lto = "thin"` does the same across crate boundaries (e.g. inlining
  `tp-parse::read_pod` into `arbiter`), at a small link-time cost.

**Where.** `#[inline(always)]` on `read_pod` (`tp-parse/src/lib.rs:61` — the
single hottest function, called per message); `#[inline]` on the whole
`tp-parse` API surface (`l2.rs:9,22`, `lib.rs:107,123,148,154,171`,
`msg.rs:37,126,146,163,182,189`), on `GapDetector::observe` (`gapdetect/src/
lib.rs:91`), on the arbiter's `push`/`drain`/`resolve` (`arbiter/src/lib.rs:126,
140,248,266`), on `push_spin` (`pipeline.rs:47`), and on `AfXdp::poll`
(`afxdp.rs:126`). Profile: root `Cargo.toml:28`.

---

## 12. In-place processing in the ring slot (no second copy)

**What.** The arbiter thread reads a frame out of the ring *without* copying it
out — `read_chunk` borrows the slot, the callback runs against those bytes, then
`commit_all` releases the slot.

**Why.** Avoids another 1.5 KB memcpy per frame on the hot path.

**Where.** `crates/arbiter/src/pipeline.rs:124`.

---

## 13. Thread pinning

**What.** Replay workers pin to cores via `core_affinity`; the AF_XDP backend
pins with `sched_setaffinity` before touching the rings.

**Why.** Prevents the OS scheduler from migrating a spinning thread, which causes
cache-cold resumption and tail latency. (macOS ignores pinning, which is why the
benchmarks note scheduler-dominated tail latencies.)

**Where.** `crates/replay/src/lib.rs:241` (`parse_workers`),
`crates/capture/src/afxdp.rs:74`.

---

## 14. Spin-based pacing (no `sleep`)

**What.** `Pacer::wait` busy-spins `while Instant::now() < due {}` instead of
calling `thread::sleep`.

**Why.** `sleep` rounds up to the OS timer granularity (~1 ms, and ~50 µs even
with high-res timers) — far too coarse to pace at 500k–2M pps and measure
sub-microsecond handoff latency. Spinning gives nanosecond-precision pacing at
the cost of burning a core.

**Where.** `crates/replay/src/lib.rs:105`.

---

## 15. Cheap peek (no full decode when you only need type+time)

**What.** `peek_kind_ts` reads only the `[type, flag, timestamp]` prefix shared by
every DEEP/TOPS message, instead of decoding all fields.

**Why.** 0.52 ns/msg vs 4.8 ns/msg. `replay --no-decode` uses it, and it is the
minimal touch needed when a consumer only routes or timestamps messages.

**Where.** `crates/tp-parse/src/msg.rs:183`.

---

## 16. Metrics and bookkeeping off the hot path

**What.** Counters are plain per-thread `u64`s (no atomics); the HDR histogram
clamps out-of-range values instead of panicking; reports are built on demand from
accumulated state, not during the loop.

**Why.** An atomic increment per packet costs more than the parse; a histogram
allocation mid-loop would be catastrophic. `record_ns` clamps to `[1, 60e9]` so a
bad value can never panic the hot loop.

**Where.** `crates/metrics/src/lib.rs:11` (counters), `:58` (clamp),
`crates/arbiter/src/lib.rs:220` (`report()` built off the hot path).

---

## 17. `black_box` keeps the benchmarks honest

**What.** Benchmarks and the replay worker feed their results through
`std::hint::black_box` (and accumulate a checksum of the decoded values).

**Why.** Without it, the optimizer sees that the loop's output is never used and
deletes the entire parse. `black_box` pretends the value escapes, forcing the
real work to run — so the numbers measure parsing, not an empty loop.

**Where.** `crates/tp-parse/benches/parse.rs:25` and `crates/replay/src/lib.rs:235`.

---

## 18. Saturating / no-panic arithmetic

**What.** Sequence arithmetic and timestamp spans use `saturating_sub` /
`wrapping_add` rather than plain operators where under/overflow could occur.

**Why.** A panic on the capture path is a data-loss incident, not an error
message. Saturating math degrades gracefully (e.g. `capture_span_ns()` at
`gapdetect/src/lib.rs:73`) and `wrapping_add` on the benchmark checksum
(`replay/src/lib.rs:218`) avoids any overflow check cost on the hot loop.

---

## Summary table (measured where available)

| # | Optimization | Effect |
|---|---|---|
| 2 | L2 fast path | 1.26 vs 13.1 ns/frame (~11×) |
| 3 | `read_pod` packed read | header + iterate = 9.6 ns/frame |
| 11 | full decode per message | 4.8 ns/msg; peek 0.52 ns/msg |
| — | whole frame pipeline | 23.6 ns/frame (42.4 Mpps single core) |
| — | replay, cache-hot | 50.4 Mpps/core (265 Mmsg/s) |
| — | replay, DRAM-streamed | 35.7 Mpps/core |
| 10 | `.tri` storage | 192 MB → 84.4 MB (2.28×), ~1 ms range read |

The budget at 60 Mpps / 8 cores is 133 ns/pkt; the measured per-packet software
cost is 21–28 ns, which is why the four "no" rules — no copy, no alloc, no lock,
no syscall — are non-negotiable.
