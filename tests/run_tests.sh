#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_BASE="/tmp/if_flow_test.jsonl"
DAY="$(date +%F)"
OUT_FILE="/tmp/if_flow_test-${DAY}.jsonl"
OUT_BASE_NOID="/tmp/if_flow_test_noid.jsonl"
OUT_FILE_NOID="/tmp/if_flow_test_noid-${DAY}.jsonl"

cd "${ROOT_DIR}"

rm -f "${OUT_BASE}" "${OUT_FILE}" "${OUT_BASE_NOID}" "${OUT_FILE_NOID}"

echo "[1/3] build check"
make >/dev/null

echo "[2/3] selftest run"
./if_flow --selftest --json-path "${OUT_BASE}" >/tmp/if_flow_test_stdout.log

if [[ ! -f "${OUT_FILE}" ]]; then
    echo "missing output file: ${OUT_FILE}" >&2
    exit 1
fi

echo "[3/3] output validation"
grep -q '"iface":"any"' "${OUT_FILE}"
grep -q '"attr_source":"ebpf"' "${OUT_FILE}"
grep -q '"cmdline":"curl https://example.org"' "${OUT_FILE}"
grep -q '"sni":"example.org"' "${OUT_FILE}"
grep -q '"host_name":"api.example.org"' "${OUT_FILE}"
grep -q '"class":"named_app"' "${OUT_FILE}"
grep -q '"bytes_human":"' "${OUT_FILE}"
grep -q '"minute_iso":"' "${OUT_FILE}"
grep -q '"record_type":"update"' "${OUT_FILE}"
grep -q '"record_type":"final"' "${OUT_FILE}"
grep -q '"first_seen_iso":"' "${OUT_FILE}"
grep -q '"last_seen_iso":"' "${OUT_FILE}"
grep -q '"connection_inferred":false' "${OUT_FILE}"
grep -q '"tcp_seen_without_syn":false' "${OUT_FILE}"
grep -q '"connections_effective":1' "${OUT_FILE}"
grep -q '"connections":1' "${OUT_FILE}"

echo "[4/4] json validation"
python3 - <<'PY' "${OUT_FILE}"
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    rows = [json.loads(line) for line in fh if line.strip()]

assert rows, "empty jsonl"
assert any(row["record_type"] == "update" for row in rows)
assert any(row["record_type"] == "final" for row in rows)
for row in rows:
    assert row["record_type"] in {"update", "final"}
    assert "minute_iso" in row
    assert "first_seen_iso" in row
    assert "last_seen_iso" in row
    assert "bytes_human" in row
    assert isinstance(row["connection_inferred"], bool)
    assert isinstance(row["tcp_seen_without_syn"], bool)
    assert isinstance(row["connections_effective"], int)
    assert row["connections_effective"] >= row["connections"]
    assert isinstance(row["connections"], int)
PY

echo "[5/5] no-identity mode"
./if_flow --selftest --no-identity-fields --json-path "${OUT_BASE_NOID}" >/tmp/if_flow_test_noid_stdout.log

if [[ ! -f "${OUT_FILE_NOID}" ]]; then
    echo "missing no-identity output file: ${OUT_FILE_NOID}" >&2
    exit 1
fi

if grep -q '"pid":' "${OUT_FILE_NOID}"; then
    echo "unexpected pid field in no-identity output" >&2
    exit 1
fi
if grep -q '"attr_source":' "${OUT_FILE_NOID}"; then
    echo "unexpected attr_source field in no-identity output" >&2
    exit 1
fi
if grep -q '"process":' "${OUT_FILE_NOID}"; then
    echo "unexpected process field in no-identity output" >&2
    exit 1
fi
if grep -q '"cmdline":' "${OUT_FILE_NOID}"; then
    echo "unexpected cmdline field in no-identity output" >&2
    exit 1
fi

echo "[6/6] archive smoke"
bash ./tests/archive_smoke.sh

echo "[7/7] install layout smoke"
bash ./tests/install_layout_smoke.sh

echo "[8/9] size rotation smoke"
bash ./tests/size_rotation_smoke.sh

echo "[9/9] uploader smoke"
bash ./tests/uploader_smoke.sh

echo "tests passed"
