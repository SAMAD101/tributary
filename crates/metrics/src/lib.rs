//! Tiny metrics layer. Everything here is per-thread and plain (no atomics on
//! the hot path); a snapshot is taken by the control plane.

use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use serde::Serialize;

/// Per-core packet/message/byte counters. Bump these in the hot loop.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counters {
    pub packets: u64,
    pub messages: u64,
    pub bytes: u64,
}

impl Counters {
    #[inline]
    pub fn add(&mut self, packets: u64, messages: u64, bytes: u64) {
        self.packets += packets;
        self.messages += messages;
        self.bytes += bytes;
    }
    pub fn rates(&self, elapsed: Duration) -> Rates {
        let s = elapsed.as_secs_f64().max(1e-9);
        Rates { pps: self.packets as f64 / s, mps: self.messages as f64 / s, gbps: self.bytes as f64 * 8.0 / s / 1e9, elapsed_s: s }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Rates {
    pub pps: f64,
    pub mps: f64,
    pub gbps: f64,
    pub elapsed_s: f64,
}

impl std::fmt::Display for Rates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.3} Mpps  {:.3} Mmsg/s  {:.3} Gbit/s  over {:.2}s", self.pps / 1e6, self.mps / 1e6, self.gbps, self.elapsed_s)
    }
}

/// Latency histogram in nanoseconds (1 ns .. 60 s, 3 significant digits).
pub struct Latency {
    h: Histogram<u64>,
}

impl Default for Latency {
    fn default() -> Self { Self::new() }
}

impl Latency {
    pub fn new() -> Self {
        Self { h: Histogram::new_with_bounds(1, 60_000_000_000, 3).unwrap() }
    }
    #[inline]
    pub fn record_ns(&mut self, ns: u64) {
        // saturating: values above the bound are clamped, never panic on the hot path
        let _ = self.h.record(ns.clamp(1, 60_000_000_000));
    }
    #[inline]
    pub fn record(&mut self, d: Duration) { self.record_ns(d.as_nanos() as u64) }
    pub fn merge(&mut self, other: &Latency) { let _ = self.h.add(&other.h); }
    pub fn count(&self) -> u64 { self.h.len() }
    pub fn summary(&self) -> LatencySummary {
        LatencySummary {
            count: self.h.len(),
            p50_ns: self.h.value_at_quantile(0.50),
            p90_ns: self.h.value_at_quantile(0.90),
            p99_ns: self.h.value_at_quantile(0.99),
            p999_ns: self.h.value_at_quantile(0.999),
            p9999_ns: self.h.value_at_quantile(0.9999),
            max_ns: self.h.max(),
            mean_ns: self.h.mean(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct LatencySummary {
    pub count: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub p9999_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
}

impl std::fmt::Display for LatencySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "n={} p50={} p90={} p99={} p99.9={} p99.99={} max={} mean={:.0} (ns)",
            self.count, self.p50_ns, self.p90_ns, self.p99_ns, self.p999_ns, self.p9999_ns, self.max_ns, self.mean_ns)
    }
}

/// Wall-clock stopwatch for rate snapshots.
pub struct Stopwatch(Instant);
impl Default for Stopwatch { fn default() -> Self { Self::start() } }
impl Stopwatch {
    pub fn start() -> Self { Self(Instant::now()) }
    pub fn elapsed(&self) -> Duration { self.0.elapsed() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_and_latency() {
        let mut c = Counters::default();
        c.add(1_000_000, 5_000_000, 100_000_000);
        let r = c.rates(Duration::from_secs(1));
        assert!((r.pps - 1e6).abs() < 1.0 && (r.mps - 5e6).abs() < 1.0 && (r.gbps - 0.8).abs() < 1e-9);
        let mut l = Latency::new();
        for i in 1..=1000 { l.record_ns(i * 100); }
        let s = l.summary();
        assert_eq!(s.count, 1000);
        assert!((s.p50_ns as i64 - 50_000).abs() < 100, "{s}");
        assert!(s.max_ns >= 99_900);
    }
}
