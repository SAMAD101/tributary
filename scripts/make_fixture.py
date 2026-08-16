#!/usr/bin/env python3
"""Cut a small classic-pcap fixture out of an IEX HIST pcapng.gz.

usage: make_fixture.py IN.pcap.gz OUT.pcap [--start-utc HH:MM] [--count N]
Skips packets until the first IEX-TP segment with message_count>0 whose send
time is >= --start-utc, then writes --count consecutive packets (heartbeats included).
"""
import argparse, gzip, struct, datetime as dt
import dpkt

ap = argparse.ArgumentParser()
ap.add_argument("src"); ap.add_argument("dst")
ap.add_argument("--start-utc", default="14:30")
ap.add_argument("--count", type=int, default=2000)
a = ap.parse_args()

hh, mm = map(int, a.start_utc.split(":"))
with gzip.open(a.src, "rb") as f:
    rd = dpkt.pcapng.Reader(f)
    started = False
    n = 0
    with open(a.dst, "wb") as out:
        wr = dpkt.pcap.Writer(out, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, buf in rd:
            if not started:
                eth = dpkt.ethernet.Ethernet(buf)
                udp = eth.data.data
                hdr = udp.data[:40]
                _, proto, chan, sess, plen, mcount, soff, fseq, stime = struct.unpack("<BxHIIHHqqq", hdr)
                t = dt.datetime.fromtimestamp(stime / 1e9, dt.timezone.utc)
                if mcount == 0 or (t.hour, t.minute) < (hh, mm):
                    continue
                started = True
            wr.writepkt(buf, ts)
            n += 1
            if n >= a.count:
                break
print(f"wrote {n} packets to {a.dst}")
