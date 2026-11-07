//! `tributary` CLI — wires the crates together. Control plane only; the hot
//! loops live in the crates.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use arbiter::{pipeline, Emit};
use capture::{CaptureSource, PcapFile};
use clap::{Parser, Subcommand};
use gapdetect::GapDetector;
use tp_parse::{l2, Segment};

#[derive(Parser)]
#[command(name = "tributary", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse a pcap/pcapng(.gz) of IEX-TP and print a per-session gap report.
    Gaps {
        file: PathBuf,
        #[arg(long)]
        json: bool,
        /// Print at most this many gap ranges.
        #[arg(long, default_value_t = 20)]
        max_gaps: usize,
    },
    /// Fan one pcap into site A / site B pcaps with independent seeded loss; writes truth.json.
    Absplit {
        input: PathBuf,
        #[arg(long, default_value = "out")]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 0.01)]
        loss_a: f64,
        #[arg(long, default_value_t = 0.01)]
        loss_b: f64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Site B extra latency (µs) relative to A.
        #[arg(long, default_value_t = 200)]
        delay_b_us: i64,
        #[arg(long, default_value_t = 20)]
        jitter_us: u64,
    },
    /// Arbitrate two site pcaps into one stream; prints the recovery report. With --truth, verifies it.
    Arbiter {
        a: PathBuf,
        b: PathBuf,
        #[arg(long)]
        truth: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Reorder window (messages, power of two).
        #[arg(long, default_value_t = 65536)]
        window: usize,
        /// Write the merged stream as a Tributary store (.tri) here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Max time to wait for the slower site's ring before proceeding one-sided (µs).
        #[arg(long, default_value_t = 20)]
        max_wait_us: u64,
        /// zstd level for --out (1 = fastest).
        #[arg(long, default_value_t = 1)]
        zstd_level: i32,
    },
    /// Inspect or read a .tri store written by `arbiter --out`.
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Load a pcap into memory and replay it through the pipeline at a controlled rate, on N cores.
    Replay {
        file: PathBuf,
        /// Packets/sec per core: "max", "2m", "500k", "12345".
        #[arg(long, default_value = "max")]
        rate: replay::Rate,
        /// Independent parse→decode→gapdetect workers, one per core.
        #[arg(long, default_value_t = 1)]
        cores: usize,
        /// Replay the file this many times per worker.
        #[arg(long, default_value_t = 20)]
        repeat: usize,
        #[arg(long, default_value_t = 64)]
        batch: usize,
        /// Only walk headers + sequence numbers; skip full message decode.
        #[arg(long)]
        no_decode: bool,
        /// Instead: split into A/B in memory (with loss) and run the concurrent arbiter pipeline.
        #[arg(long)]
        arbiter: bool,
        #[arg(long, default_value_t = 0.01)]
        loss_a: f64,
        #[arg(long, default_value_t = 0.01)]
        loss_b: f64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Max time the arbiter waits for the slower site's ring (µs).
        #[arg(long, default_value_t = 20)]
        max_wait_us: u64,
        #[arg(long)]
        json: bool,
    },
    /// Live capture (feature `libpcap` and/or `afxdp`) → gap detector; prints stats every second.
    Live {
        /// libpcap | afxdp
        #[arg(long, default_value = "libpcap")]
        backend: String,
        #[arg(long)]
        iface: String,
        /// BPF filter (libpcap only), e.g. "udp and dst port 10378"
        #[arg(long)]
        filter: Option<String>,
        /// RSS queue (afxdp only). Run one process/thread per queue.
        #[arg(long, default_value_t = 0)]
        queue: u32,
        /// Pin to this core (afxdp only).
        #[arg(long)]
        core: Option<usize>,
        /// Stop after this many seconds (0 = run until Ctrl-C).
        #[arg(long, default_value_t = 0)]
        seconds: u64,
    },
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Print index summary: blocks, messages, compression ratio, gaps.
    Info { file: PathBuf },
    /// Read a (session, seq) range or a capture-time range and print records.
    Read {
        file: PathBuf,
        #[arg(long)]
        session: Option<u32>,
        #[arg(long)]
        from_seq: Option<u64>,
        #[arg(long)]
        to_seq: Option<u64>,
        /// Capture time range, ns since epoch.
        #[arg(long)]
        from_ns: Option<u64>,
        #[arg(long)]
        to_ns: Option<u64>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Gaps { file, json, max_gaps } => gaps(file, json, max_gaps),
        Cmd::Absplit { input, out_dir, loss_a, loss_b, seed, delay_b_us, jitter_us } => {
            std::fs::create_dir_all(&out_dir)?;
            let cfg = absplit::SplitConfig { loss_a, loss_b, seed, delay_a_ns: 0, delay_b_ns: delay_b_us * 1000, jitter_ns: jitter_us * 1000 };
            let (a, b, t) = (out_dir.join("a.pcap"), out_dir.join("b.pcap"), out_dir.join("truth.json"));
            let truth = absplit::split_pcap(&input, &a, &b, cfg).context("split")?;
            std::fs::write(&t, serde_json::to_vec_pretty(&truth)?)?;
            println!("in: {} pkts / {} msgs", truth.packets_in, truth.messages_in);
            println!("A: {} kept, {} dropped ({} msgs in {} ranges) -> {}", truth.packets_a, truth.dropped_pkts_a, sum(&truth.dropped_a), truth.dropped_a.len(), a.display());
            println!("B: {} kept, {} dropped ({} msgs in {} ranges) -> {}", truth.packets_b, truth.dropped_pkts_b, sum(&truth.dropped_b), truth.dropped_b.len(), b.display());
            println!("dropped by BOTH (unrecoverable): {} msgs in {} ranges -> {}", sum(&truth.dropped_both), truth.dropped_both.len(), t.display());
            Ok(())
        }
        Cmd::Arbiter { a, b, truth, json, window, out, max_wait_us, zstd_level } => arbitrate(a, b, truth, json, window, out, max_wait_us, zstd_level),
        Cmd::Live { backend, iface, filter, queue, core, seconds } => live(&backend, &iface, filter.as_deref(), queue, core, seconds),
        Cmd::Store { cmd } => store_cmd(cmd),
        Cmd::Replay { file, rate, cores, repeat, batch, no_decode, arbiter, loss_a, loss_b, seed, max_wait_us, json } => {
            if arbiter { replay_arbiter(file, rate, repeat, loss_a, loss_b, seed, max_wait_us, json) } else { replay_parse(file, rate, cores, repeat, batch, !no_decode, json) }
        }
    }
}

fn replay_parse(file: PathBuf, rate: replay::Rate, cores: usize, repeat: usize, batch: usize, decode: bool, json: bool) -> Result<()> {
    let data = std::sync::Arc::new(replay::Loaded::load(&file).with_context(|| format!("load {}", file.display()))?);
    eprintln!("loaded {} packets / {} msgs / {:.1} MB; {cores} core(s) × {repeat} passes, rate {rate:?}, batch {batch}, decode {decode}", data.packets(), data.messages, data.bytes as f64 / 1e6);
    let t0 = std::time::Instant::now();
    let results = replay::parse_workers(data.clone(), cores, rate, repeat, batch, decode);
    let wall = t0.elapsed();
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }
    let mut tot = metrics::Counters::default();
    for r in &results {
        tot.add(r.counters.packets, r.counters.messages, r.counters.bytes);
        println!("core {:>3}: {}  per-pkt-cycle {}", r.core.map(|c| c.to_string()).unwrap_or("?".into()), r.rates, r.per_packet);
        if r.gaps > 0 || r.decode_errors > 0 { println!("          gaps {} decode errors {}", r.gaps, r.decode_errors); }
    }
    println!("aggregate ({cores} cores): {}", tot.rates(wall));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replay_arbiter(file: PathBuf, rate: replay::Rate, repeat: usize, loss_a: f64, loss_b: f64, seed: u64, max_wait_us: u64, json: bool) -> Result<()> {
    let data = replay::Loaded::load(&file).with_context(|| format!("load {}", file.display()))?;
    let cfg = absplit::SplitConfig { loss_a, loss_b, seed, ..Default::default() };
    let mut sp = absplit::Splitter::new(cfg);
    let (mut la, mut lb) = (replay::Loaded::empty(), replay::Loaded::empty());
    for p in data.iter() {
        let Some(seg) = l2::udp_payload_fast(p.data).and_then(|u| Segment::parse(u).ok()) else { continue };
        let r = sp.route(&seg.header, p.ts_ns);
        if r.keep_a { la.push(r.ts_a, p.data); }
        if r.keep_b { lb.push(r.ts_b, p.data); }
    }
    let truth = sp.finish();
    drop(data);
    let (la, lb) = (std::sync::Arc::new(la), std::sync::Arc::new(lb));
    eprintln!("A/B split in memory: A {} pkts, B {} pkts (loss {loss_a}/{loss_b}, both-lost {} msgs); {repeat} passes at {rate:?}", la.packets(), lb.packets(), truth.dropped_both.iter().map(|g| g.len()).sum::<u64>());
    let (mut emitted, mut gaps) = (0u64, 0u64);
    let mut lat = metrics::Latency::new();
    let (report, stats) = pipeline::run_dual(
        replay::MemSource::new(la, rate, repeat), replay::MemSource::new(lb, rate, repeat),
        arbiter::Config::default(), 4096, Duration::from_micros(max_wait_us),
        |e, enq| match e {
            Emit::Msg(_) => { emitted += 1; if emitted % 16 == 0 { lat.record(enq.elapsed()); } }
            Emit::Gap { .. } => gaps += 1,
        })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "report": report, "packets": stats.packets, "wall_s": stats.wall.as_secs_f64(), "emitted": emitted, "latency": lat.summary() }))?);
        return Ok(());
    }
    let s = &report.sessions[0];
    let pk = (stats.packets[0] + stats.packets[1]) as f64;
    println!("arbiter core: {:.3} Mpps in (A+B), {:.3} Mmsg/s emitted, wall {:.2?}", pk / stats.wall.as_secs_f64() / 1e6, emitted as f64 / stats.wall.as_secs_f64() / 1e6, stats.wall);
    println!("emitted {} msgs; residual gaps {} ranges / {} msgs (expected from truth ≈ {} msgs × {repeat}); forced advances {}", s.emitted, s.residual_gaps.len(), s.residual_missing, truth.dropped_both.iter().map(|g| g.len()).sum::<u64>(), s.forced_advances);
    println!("wins A {} (+{} window)  B {} (+{} window)  dups A {} B {}", s.site[0].wins, s.site[0].wins_from_buffer, s.site[1].wins, s.site[1].wins_from_buffer, s.site[0].dups, s.site[1].dups);
    println!("ring-handoff+arbitration latency (sampled 1/16): {}", lat.summary());
    Ok(())
}

#[allow(unused_variables, unreachable_code)]
fn live(backend: &str, iface: &str, filter: Option<&str>, queue: u32, core: Option<usize>, seconds: u64) -> Result<()> {
    let src: Box<dyn CaptureSource> = match backend {
        #[cfg(feature = "libpcap")]
        "libpcap" => Box::new(capture::LiveLibpcap::open(iface, filter, 2048)?),
        #[cfg(all(feature = "afxdp", target_os = "linux"))]
        "afxdp" => Box::new(capture::AfXdp::open(&capture::afxdp::AfXdpConfig { ifname: iface.to_string(), queue_id: queue, pin_core: core, ..Default::default() })?),
        other => anyhow::bail!("backend {other:?} not available in this build (features: libpcap, afxdp[linux])"),
    };
    run_live(src, seconds)
}

fn run_live(mut src: Box<dyn CaptureSource>, seconds: u64) -> Result<()> {
    let mut det = GapDetector::new();
    let (mut pkts, mut bytes, mut non_iex) = (0u64, 0u64, 0u64);
    let t0 = std::time::Instant::now();
    let mut last = t0;
    let (mut lp, mut lb) = (0u64, 0u64);
    loop {
        let n = src.poll(64, &mut |p| {
            pkts += 1;
            bytes += p.data.len() as u64;
            match l2::udp_payload_fast(p.data).and_then(|u| Segment::parse(u).ok()) {
                Some(seg) => { det.observe(&seg.header, p.ts_ns); }
                None => non_iex += 1,
            }
        })?;
        if n.is_none() { break; }
        if last.elapsed().as_secs() >= 1 {
            let dt = last.elapsed().as_secs_f64();
            let (missing, msgs) = (det.total_missing(), det.total_messages());
            println!("{:>7.1}s  {:>9.0} pps  {:>7.2} Mbit/s  msgs {msgs}  missing {missing}  non-iex {non_iex}", t0.elapsed().as_secs_f64(), (pkts - lp) as f64 / dt, (bytes - lb) as f64 * 8.0 / dt / 1e6);
            (lp, lb, last) = (pkts, bytes, std::time::Instant::now());
            if seconds > 0 && t0.elapsed().as_secs() >= seconds { break; }
        }
    }
    for s in det.report() {
        println!("session {:#x}: msgs {} gaps {} missing {} dups {}", s.session_id, s.messages, s.gap_count, s.missing_msgs, s.duplicate_msgs);
    }
    Ok(())
}

fn sum(g: &[gapdetect::GapRange]) -> u64 { g.iter().map(|g| g.len()).sum() }

fn gaps(file: PathBuf, json: bool, max_gaps: usize) -> Result<()> {
    let mut src = PcapFile::open(&file).with_context(|| format!("open {}", file.display()))?;
    let mut det = GapDetector::new();
    let (mut pkts, mut non_iex) = (0u64, 0u64);
    let t0 = std::time::Instant::now();
    src.for_each(64, &mut |p| {
        pkts += 1;
        match l2::udp_payload_fast(p.data).and_then(|u| Segment::parse(u).ok()) {
            Some(seg) => { det.observe(&seg.header, p.ts_ns); }
            None => non_iex += 1,
        }
    })?;
    let el = t0.elapsed();
    let rep = det.report();
    if json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
        return Ok(());
    }
    println!("{}: {pkts} packets ({non_iex} non-IEX) in {el:.2?} ({:.2} Mpps)", file.display(), pkts as f64 / el.as_secs_f64() / 1e6);
    for s in &rep {
        println!("session {:#x} channel {} proto {:#06x}", s.session_id, s.channel_id, s.message_protocol_id);
        println!("  segments {} (heartbeats {})  messages {}  seq {}..={}", s.segments, s.heartbeats, s.messages, s.first_seq, s.last_seq);
        println!("  capture span {:.3}s  send span {:.3}s", s.capture_span_ns() as f64 / 1e9, s.send_span_ns() as f64 / 1e9);
        println!("  gaps {}  missing msgs {}  duplicates {} segs / {} msgs  reordered {} segs / {} msgs", s.gap_count, s.missing_msgs, s.duplicate_segments, s.duplicate_msgs, s.reordered_segments, s.reordered_msgs);
        for g in s.gaps.iter().take(max_gaps) { println!("    gap {}..={} ({} msgs)", g.from, g.to, g.len()); }
        if s.gaps.len() > max_gaps { println!("    ... {} more", s.gaps.len() - max_gaps); }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn arbitrate(a: PathBuf, b: PathBuf, truth: Option<PathBuf>, json: bool, window: usize, out: Option<PathBuf>, max_wait_us: u64, zstd_level: i32) -> Result<()> {
    let sa = PcapFile::open(&a).with_context(|| format!("open {}", a.display()))?;
    let sb = PcapFile::open(&b).with_context(|| format!("open {}", b.display()))?;
    let (mut emitted, mut gaps) = (0u64, 0u64);
    let mut lat = metrics::Latency::new();
    let mut writer = out.as_ref().map(|p| store::Writer::create(p, 4096, zstd_level)).transpose().context("create store")?;
    let mut store_err: Option<store::StoreError> = None;
    let (report, stats) = pipeline::run_dual(sa, sb, arbiter::Config { window }, 4096, Duration::from_micros(max_wait_us), |e, enq| {
        match e {
            Emit::Msg(m) => {
                emitted += 1;
                if emitted % 16 == 0 { lat.record(enq.elapsed()); }
                if let Some(w) = writer.as_mut() {
                    if let Err(e) = w.push(&store::Record { session_id: m.session_id, seq: m.seq, capture_ns: m.capture_ns, send_ns: m.send_ns, site: m.site as u8, body: m.body }) { store_err = Some(e); }
                }
            }
            Emit::Gap { session_id, from, to } => { gaps += 1; if let Some(w) = writer.as_mut() { w.push_gap(session_id, from, to); } }
        }
    })?;
    if let Some(e) = store_err { return Err(e.into()); }
    let store_idx = writer.map(|w| w.finish()).transpose()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("A: {} pkts  B: {} pkts  wall {:.2?}  emitted {emitted} msgs ({:.2} Mmsg/s)", stats.packets[0], stats.packets[1], stats.wall, emitted as f64 / stats.wall.as_secs_f64() / 1e6);
    println!("ring-handoff+arbitration latency (sampled 1/16): {}", lat.summary());
    if let (Some(idx), Some(p)) = (store_idx, out.as_ref()) {
        println!("store {}: {} msgs in {} blocks, raw {:.1} MB -> {:.1} MB on disk (ratio {:.2}x), {:.0} MB/s raw / {:.2} Mmsg/s written (pipeline wall)",
            p.display(), idx.messages, idx.blocks.len(), idx.raw_bytes as f64 / 1e6, idx.compressed_bytes as f64 / 1e6,
            idx.raw_bytes as f64 / idx.compressed_bytes.max(1) as f64, idx.raw_bytes as f64 / 1e6 / stats.wall.as_secs_f64(), idx.messages as f64 / 1e6 / stats.wall.as_secs_f64());
    }
    for s in &report.sessions {
        println!("session {:#x}: emitted {} seq {}..={}", s.session_id, s.emitted, s.first_seq, s.next_seq.saturating_sub(1));
        for (i, name) in ["A", "B"].iter().enumerate() {
            let x = &s.site[i];
            println!("  site {name}: in {} msgs  wins {} (+{} via window)  buffered {}  dups {}  late-after-gap {}", x.msgs_in, x.wins, x.wins_from_buffer, x.buffered, x.dups, x.late_after_gap);
        }
        println!("  A lost {} ranges / {} msgs -> recovered from B: {} ranges / {} msgs", s.site_a_gaps.len(), sum(&s.site_a_gaps), s.recovered_from_b.len(), sum(&s.recovered_from_b));
        println!("  B lost {} ranges / {} msgs -> recovered from A: {} ranges / {} msgs", s.site_b_gaps.len(), sum(&s.site_b_gaps), s.recovered_from_a.len(), sum(&s.recovered_from_a));
        println!("  residual (missing from BOTH): {} ranges / {} msgs  forced advances {}", s.residual_gaps.len(), s.residual_missing, s.forced_advances);
        for g in s.residual_gaps.iter().take(10) { println!("    {}..={}", g.from, g.to); }
    }
    if let Some(t) = truth {
        let truth: absplit::Truth = serde_json::from_slice(&std::fs::read(&t)?)?;
        let s = &report.sessions[0];
        let (lo, hi) = (s.first_seq, s.next_seq - 1);
        let both: Vec<_> = truth.dropped_both.iter().filter_map(|g| {
            let (f, t) = (g.from.max(lo), g.to.min(hi));
            (f <= t).then_some(gapdetect::GapRange { from: f, to: t })
        }).collect();
        let ok = s.residual_gaps == both;
        println!("ground truth: residual gaps {} dropped_A ∩ dropped_B ({} msgs) — {}", if ok { "==" } else { "!=" }, sum(&both), if ok { "PASS" } else { "FAIL" });
        anyhow::ensure!(ok, "arbiter output does not match ground truth");
    }
    Ok(())
}

fn store_cmd(cmd: StoreCmd) -> Result<()> {
    match cmd {
        StoreCmd::Info { file } => {
            let s = store::Store::open(&file)?;
            let i = &s.index;
            println!("{}: {} msgs, {} blocks (≤{} msgs each), raw {:.1} MB, compressed {:.1} MB, ratio {:.2}x", file.display(), i.messages, i.blocks.len(), s.block_msgs, i.raw_bytes as f64 / 1e6, i.compressed_bytes as f64 / 1e6, s.compression_ratio());
            let mut sessions: Vec<u32> = i.blocks.iter().map(|b| b.session).collect();
            sessions.dedup();
            for sid in sessions {
                let bs: Vec<_> = i.blocks.iter().filter(|b| b.session == sid).collect();
                println!("  session {:#x}: seq {}..={}  capture {}..{} ns  ({} blocks)", sid, bs[0].first_seq, bs.last().unwrap().last_seq, bs[0].first_ns, bs.last().unwrap().last_ns, bs.len());
            }
            println!("  residual gaps recorded: {} ({} msgs)", i.gaps.len(), i.gaps.iter().map(|(_, g)| g.len()).sum::<u64>());
        }
        StoreCmd::Read { file, session, from_seq, to_seq, from_ns, to_ns, limit } => {
            let mut s = store::Store::open(&file)?;
            let mut n = 0usize;
            let mut show = |r: store::Record<'_>| {
                if n < limit {
                    let m = tp_parse::decode(r.body).map(|m| format!("{m:?}")).unwrap_or_else(|e| format!("<{e}>"));
                    println!("{:#x} seq {} site {} cap {} send {} {}", r.session_id, r.seq, if r.site == 0 { "A" } else { "B" }, r.capture_ns, r.send_ns, m);
                }
                n += 1;
            };
            let t0 = std::time::Instant::now();
            let total = if let (Some(lo), Some(hi)) = (from_ns, to_ns) {
                s.read_time_range(lo, hi, &mut show)?
            } else {
                let sid = session.or_else(|| s.index.blocks.first().map(|b| b.session)).context("empty store")?;
                s.read_seq_range(sid, from_seq.unwrap_or(0), to_seq.unwrap_or(u64::MAX), &mut show)?
            };
            println!("{total} records in range ({} shown) in {:.2?}", n.min(limit), t0.elapsed());
        }
    }
    Ok(())
}
