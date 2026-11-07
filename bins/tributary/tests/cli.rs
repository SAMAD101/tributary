//! End-to-end: gaps → absplit → arbiter --truth --out → store read, through the real binary.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tributary");
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/deep_20191224_1430.pcap.gz");

fn run(args: &[&str]) -> String {
    let out = Command::new(BIN).args(args).output().expect("run tributary");
    let s = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "tributary {args:?} failed:\n{s}");
    s
}

#[test]
fn gaps_absplit_arbiter_store_roundtrip() {
    let dir = std::env::temp_dir().join(format!("tributary-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_str().unwrap();

    let g = run(&["gaps", FIXTURE]);
    assert!(g.contains("messages 10520"), "{g}");
    assert!(g.contains("gaps 0  missing msgs 0"), "{g}");

    let s = run(&["absplit", FIXTURE, "--out-dir", d, "--loss-a", "0.05", "--loss-b", "0.05", "--seed", "3"]);
    assert!(s.contains("in: 2000 pkts / 10520 msgs"), "{s}");

    let tri = format!("{d}/merged.tri");
    let a = run(&["arbiter", &format!("{d}/a.pcap"), &format!("{d}/b.pcap"), "--truth", &format!("{d}/truth.json"), "--out", &tri]);
    assert!(a.contains("PASS"), "{a}");

    let i = run(&["store", "info", &tri]);
    assert!(i.contains("session 0x474e0000: seq 57244..=67763"), "{i}");
    let r = run(&["store", "read", &tri, "--from-seq", "60000", "--to-seq", "60009", "--limit", "10"]);
    assert!(r.contains("seq 60000 "), "{r}");
    assert!(r.contains("records in range"), "{r}");

    let rp = run(&["replay", FIXTURE, "--cores", "2", "--repeat", "5"]);
    assert!(rp.contains("aggregate (2 cores)"), "{rp}");
    let ra = run(&["replay", FIXTURE, "--arbiter", "--repeat", "3", "--rate", "500k"]);
    assert!(ra.contains("residual gaps 0 ranges"), "{ra}");
    std::fs::remove_dir_all(&dir).ok();
}
