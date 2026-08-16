#!/usr/bin/env python3
"""Generate golden parse output for a fixture using the reference parser
(rob-blackbourn/iex_parser) so the Rust tp-parse crate can be checked against it.

usage: reference_golden.py FIXTURE.pcap.gz DEEPv1.0|TOPSv1.6 OUT.json
Header layout follows IEX-TP v1.0 (same struct as iex_parser.parser.Header);
message bodies are decoded by iex_parser.messages.decode_message.
"""
import sys, gzip, json, struct
from decimal import Decimal
import dpkt
from iex_parser.messages import decode_message

src, proto, dst = sys.argv[1:4]
HDR = "<BxHIIHHqqq"

def fnv1a64(h, data: bytes):
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

by_type, sample, packets, msgs = {}, [], 0, 0
first_seq = last_seq = None
expected = None
contiguous = True
h = 0xcbf29ce484222325
with gzip.open(src, "rb") as f:
    for ts, buf in dpkt.pcap.Reader(f):
        eth = dpkt.ethernet.Ethernet(buf)
        payload = eth.data.data.data
        ver, mproto, chan, sess, plen, mcount, soff, fseq, stime = struct.unpack(HDR, payload[:40])
        assert ver == 1 and len(payload) == 40 + plen
        packets += 1
        if expected is not None and fseq != expected:
            contiguous = False
        expected = fseq + mcount
        off = 40
        for i in range(mcount):
            (mlen,) = struct.unpack("<H", payload[off:off + 2]); off += 2
            body = payload[off:off + mlen]; off += mlen
            m = decode_message(proto, body[0], body[1:])
            seq = fseq + i
            first_seq = seq if first_seq is None else first_seq
            last_seq = seq
            msgs += 1
            t = chr(body[0])
            by_type[t] = by_type.get(t, 0) + 1
            sym = m.get("symbol", b"").decode()
            size = m.get("size", m.get("bid_size", 0))
            price = m.get("price", m.get("bid_price", Decimal(0)))
            price_i = int(price * 10000)
            ts_s = int(m["timestamp"].timestamp())
            line = f"{seq}|{t}|{sym}|{size}|{price_i}\n".encode()
            h = fnv1a64(h, line)
            if len(sample) < 300:
                rec = {"seq": seq, "type": t, "symbol": sym, "ts_s": ts_s}
                for k in ("size", "price", "trade_id", "flags", "bid_size", "bid_price", "ask_size", "ask_price", "side"):
                    if k in m:
                        v = m[k]
                        if isinstance(v, Decimal): v = int(v * 10000)
                        if isinstance(v, bytes): v = v.decode()
                        rec[k] = v
                sample.append(rec)
out = {"file": src.split("/")[-1], "protocol": proto, "message_protocol_id": mproto,
       "packets": packets, "messages": msgs, "by_type": by_type,
       "first_seq": first_seq, "last_seq": last_seq, "seq_contiguous": contiguous,
       "fnv1a64": h, "sample": sample}
json.dump(out, open(dst, "w"), indent=1)
print({k: v for k, v in out.items() if k != "sample"})
