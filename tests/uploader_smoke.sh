#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/if_flow_uploader_test.XXXXXX)"
DAY="$(date +%F)"
YESTERDAY="$(date -d 'yesterday' +%F)"
BASE_PATH="${TMP_DIR}/if_flow.jsonl"
DATA_FILE="${TMP_DIR}/if_flow-${DAY}.jsonl"
OLD_FILE="${TMP_DIR}/if_flow-${YESTERDAY}.jsonl"
STATE_FILE="${TMP_DIR}/state.json"
SERVER_LOG="${TMP_DIR}/server.log"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

cat > "${DATA_FILE}" <<'EOF'
{"record_type":"final","host":"h1","iface":"any","minute_ts":1,"minute_iso":"2024-01-01T00:00:00+0000","proto":6,"class":"https","direction":"out","src_ip":"10.0.0.1","src_port":12345,"dst_ip":"1.1.1.1","dst_port":443,"packets":10,"bytes":1000,"bytes_human":"1000 B","connections":1,"connections_effective":1,"connection_inferred":false,"tcp_seen_without_syn":false}
{"record_type":"final","host":"h1","iface":"any","minute_ts":2,"minute_iso":"2024-01-01T00:01:00+0000","proto":17,"class":"dns","direction":"out","src_ip":"10.0.0.1","src_port":5353,"dst_ip":"8.8.8.8","dst_port":53,"packets":2,"bytes":120,"bytes_human":"120 B","connections":1,"connections_effective":1,"connection_inferred":false,"tcp_seen_without_syn":false}
EOF

IF_FLOW_JSON_PATH="${TMP_DIR}/if_flow-*.jsonl" \
IF_FLOW_UPLOADER_STATE_PATH="${STATE_FILE}" \
IF_FLOW_UPLOADER_BATCH_LINES=1 \
python3 "${ROOT_DIR}/clickhouse_uploader/if_flow_clickhouse_uploader.py" --once --dry-run >/tmp/if_flow_uploader_smoke.log

python3 - <<'PY' "${STATE_FILE}" "${DATA_FILE}"
import json
import os
import sys

state_path, data_path = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as fh:
    state = json.load(fh)
files = state.get("files", {})
assert data_path in files, "missing file state"
entry = files[data_path]
assert int(entry["offset"]) == os.path.getsize(data_path), "offset not advanced"
stats = state.get("stats", {})
assert int(stats.get("last_sent_lines", 0)) == 2, "unexpected sent lines"
assert int(stats.get("last_batches_sent", 0)) == 2, "unexpected batch count"
assert int(stats.get("runs_total", 0)) >= 1, "runs_total not updated"
PY

python3 - <<'PY' "${TMP_DIR}" "${STATE_FILE}" "${ROOT_DIR}"
import importlib.util
import json
import os
import sys

tmp_dir, state_file, root_dir = sys.argv[1:4]
bad_file = os.path.join(tmp_dir, "if_flow-2099-01-01.jsonl")
raw = (
    b'{"record_type":"final","host":"h1","iface":"any","minute_ts":5,'
    b'"minute_iso":"2024-01-01T00:04:00+0000","proto":6,"class":"other",'
    b'"direction":"out","process":"bad\xc6proc","src_ip":"10.0.0.1",'
    b'"src_port":12345,"dst_ip":"1.1.1.1","dst_port":443,"packets":1,'
    b'"bytes":10,"bytes_human":"10 B","connections":1,"connections_effective":1,'
    b'"connection_inferred":false,"tcp_seen_without_syn":false}\n'
)
with open(bad_file, "wb") as fh:
    fh.write(raw)

spec = importlib.util.spec_from_file_location(
    "if_flow_clickhouse_uploader",
    f"{root_dir}/clickhouse_uploader/if_flow_clickhouse_uploader.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.clickhouse_insert_with_retry = lambda cfg, payload: 1
cfg = {
    "base_path": os.path.join(tmp_dir, "if_flow-*.jsonl"),
    "state_path": state_file,
    "clickhouse_url": "http://127.0.0.1:8123/",
    "database": "default",
    "table": "if_flow",
    "username": "",
    "password": "",
    "batch_lines": 10,
    "batch_bytes": 1048576,
    "max_batches_per_file": 16,
    "poll_sec": 1,
    "timeout_sec": 10,
    "max_retries": 1,
    "retry_backoff_sec": 1,
    "retry_backoff_max_sec": 1,
    "delete_sent_rotated": False,
    "truncate_sent_active": False,
    "dry_run": False,
}
result = mod.run_once(cfg)
assert int(result["sent_lines"]) >= 1, "invalid utf-8 line was not uploaded"
with open(state_file, "r", encoding="utf-8") as fh:
    state = json.load(fh)
assert bad_file in state.get("files", {}), "bad file missing from state"
PY

cat > "${OLD_FILE}" <<'EOF'
{"record_type":"final","host":"h1","iface":"any","minute_ts":3,"minute_iso":"2024-01-01T00:02:00+0000","proto":6,"class":"https","direction":"out","src_ip":"10.0.0.2","src_port":23456,"dst_ip":"2.2.2.2","dst_port":443,"packets":3,"bytes":300,"bytes_human":"300 B","connections":1,"connections_effective":1,"connection_inferred":false,"tcp_seen_without_syn":false}
EOF

python3 - <<'PY' "${ROOT_DIR}" "${TMP_DIR}" "${STATE_FILE}"
import importlib.util
import sys

root_dir, tmp_dir, state_file = sys.argv[1:4]
spec = importlib.util.spec_from_file_location(
    "if_flow_clickhouse_uploader",
    f"{root_dir}/clickhouse_uploader/if_flow_clickhouse_uploader.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.clickhouse_insert_with_retry = lambda cfg, payload: 1
cfg = {
    "base_path": f"{tmp_dir}/if_flow-*.jsonl",
    "state_path": state_file,
    "clickhouse_url": "http://127.0.0.1:8123/",
    "database": "default",
    "table": "if_flow",
    "username": "",
    "password": "",
    "batch_lines": 10,
    "batch_bytes": 1048576,
    "max_batches_per_file": 16,
    "poll_sec": 1,
    "timeout_sec": 10,
    "max_retries": 1,
    "retry_backoff_sec": 1,
    "retry_backoff_max_sec": 1,
    "delete_sent_rotated": True,
    "truncate_sent_active": False,
    "dry_run": False,
}
mod.run_once(cfg)
PY

python3 - <<'PY' "${STATE_FILE}" "${OLD_FILE}"
import json
import os
import sys

state_path, old_file = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as fh:
    state = json.load(fh)
files = state.get("files", {})
assert old_file not in files, "rotated uploaded file state not removed"
assert not os.path.exists(old_file), "rotated uploaded file not deleted"
stats = state.get("stats", {})
assert int(stats.get("deleted_files_total", 0)) >= 1, "delete stat not updated"
PY

cat > "${DATA_FILE}" <<'EOF'
{"record_type":"final","host":"h1","iface":"any","minute_ts":4,"minute_iso":"2024-01-01T00:03:00+0000","proto":17,"class":"dns","direction":"out","src_ip":"10.0.0.3","src_port":34567,"dst_ip":"3.3.3.3","dst_port":53,"packets":4,"bytes":400,"bytes_human":"400 B","connections":1,"connections_effective":1,"connection_inferred":false,"tcp_seen_without_syn":false}
EOF

python3 - <<'PY' "${ROOT_DIR}" "${TMP_DIR}" "${STATE_FILE}"
import importlib.util
import sys

root_dir, tmp_dir, state_file = sys.argv[1:4]
spec = importlib.util.spec_from_file_location(
    "if_flow_clickhouse_uploader",
    f"{root_dir}/clickhouse_uploader/if_flow_clickhouse_uploader.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.clickhouse_insert_with_retry = lambda cfg, payload: 1
cfg = {
    "base_path": f"{tmp_dir}/if_flow-*.jsonl",
    "state_path": state_file,
    "clickhouse_url": "http://127.0.0.1:8123/",
    "database": "default",
    "table": "if_flow",
    "username": "",
    "password": "",
    "batch_lines": 10,
    "batch_bytes": 1048576,
    "max_batches_per_file": 16,
    "poll_sec": 1,
    "timeout_sec": 10,
    "max_retries": 1,
    "retry_backoff_sec": 1,
    "retry_backoff_max_sec": 1,
    "delete_sent_rotated": False,
    "truncate_sent_active": True,
    "dry_run": False,
}
mod.run_once(cfg)
PY

python3 - <<'PY' "${STATE_FILE}" "${DATA_FILE}"
import json
import os
import sys

state_path, data_path = sys.argv[1], sys.argv[2]
with open(state_path, "r", encoding="utf-8") as fh:
    state = json.load(fh)
files = state.get("files", {})
entry = files[data_path]
assert os.path.exists(data_path), "active file unexpectedly removed"
assert os.path.getsize(data_path) == 0, "active file not truncated"
assert int(entry["offset"]) == 0, "truncated file offset not reset"
assert int(entry["size"]) == 0, "truncated file size not reset"
stats = state.get("stats", {})
assert int(stats.get("truncated_files_total", 0)) >= 1, "truncate stat not updated"
PY

echo "uploader smoke passed"
