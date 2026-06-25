#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/if_flow_rotate_test.XXXXXX)"
OUT_BASE="${TMP_DIR}/if_flow.jsonl"
DAY="$(date +%F)"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

cd "${ROOT_DIR}"

./if_flow --selftest --json-path "${OUT_BASE}" --json-max-file-size-mb 1 >/tmp/if_flow_rotate_stdout.log

count="$(find "${TMP_DIR}" -maxdepth 1 -type f -name "if_flow-${DAY}*.jsonl" | wc -l)"
if [[ "${count}" -lt 1 ]]; then
    echo "no rotated jsonl files created" >&2
    exit 1
fi

cat > "${TMP_DIR}/append_rows.py" <<'PY'
import json
import os
import sys

tmp_dir = sys.argv[1]
day = sys.argv[2]
path = os.path.join(tmp_dir, f"if_flow-{day}.jsonl")
row = {
    "record_type": "final",
    "host": "h1",
    "iface": "any",
    "minute_ts": 10,
    "minute_iso": "2024-01-01T00:10:00+0000",
    "proto": 6,
    "class": "https",
    "direction": "out",
    "src_ip": "10.0.0.1",
    "src_port": 12345,
    "dst_ip": "1.1.1.1",
    "dst_port": 443,
    "packets": 1,
    "bytes": 100,
    "bytes_human": "100 B",
    "connections": 1,
    "connections_effective": 1,
    "connection_inferred": False,
    "tcp_seen_without_syn": False,
}
with open(path, "a", encoding="utf-8") as fh:
    for _ in range(20000):
        fh.write(json.dumps(row) + "\n")
PY

python3 "${TMP_DIR}/append_rows.py" "${TMP_DIR}" "${DAY}"

rm -f "${TMP_DIR}/append_rows.py"

./if_flow --selftest --json-path "${OUT_BASE}" --json-max-file-size-mb 1 >/tmp/if_flow_rotate_stdout2.log

count="$(find "${TMP_DIR}" -maxdepth 1 -type f -name "if_flow-${DAY}*.jsonl" | wc -l)"
if [[ "${count}" -lt 2 ]]; then
    echo "size rotation did not create chunk file" >&2
    find "${TMP_DIR}" -maxdepth 1 -type f -name "if_flow-${DAY}*.jsonl" -print >&2
    exit 1
fi

echo "size rotation smoke passed"
