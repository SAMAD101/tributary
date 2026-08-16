# scripts

- `fetch_sample.sh [YYYYMMDD] [DEEP|TOPS]` — download one IEX HIST day into `data/` (gitignored).
- `make_fixture.py IN.pcap.gz OUT.pcap --start-utc HH:MM --count N` — cut a small classic-pcap fixture (needs `.venv`: `python3 -m venv .venv && .venv/bin/pip install iex-parser dpkt`).
- `reference_golden.py FIXTURE.pcap.gz DEEPv1.0|TOPSv1.6 OUT.json` — golden output from the reference parser (rob-blackbourn/iex_parser) that `crates/tp-parse/tests/golden.rs` asserts against.

Committed fixtures (`fixtures/`): 2000 packets each of DEEP 1.0 and TOPS 1.6 from 2019-12-24 starting 14:30 UTC (09:30 ET open), ~100 KB gzipped.
