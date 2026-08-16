#!/usr/bin/env sh
# Fetch ONE IEX HIST sample day (pcapng.gz) into ./data. Default: 2019-12-24 (half day, ~160 MB each).
# usage: scripts/fetch_sample.sh [YYYYMMDD] [DEEP|TOPS]
set -eu
DATE="${1:-20191224}"; FEED="${2:-DEEP}"
mkdir -p data
LINK=$(curl -sS "https://iextrading.com/api/1.0/hist?date=$DATE" | python3 -c "
import sys,json
for x in json.load(sys.stdin):
    if x['feed']=='$FEED': print(x['link']); break")
[ -n "$LINK" ] || { echo "no $FEED file for $DATE" >&2; exit 1; }
OUT="data/${DATE}_IEXTP1_${FEED}.pcap.gz"
echo "downloading $LINK -> $OUT"
curl -L -o "$OUT" "$LINK"
