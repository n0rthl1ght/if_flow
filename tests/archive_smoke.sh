#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/if_flow_archive_test.XXXXXX)"
BASE_PATH="${TMP_DIR}/if_flow.jsonl"
TODAY="$(date +%F)"
YESTERDAY="$(date -d 'yesterday' +%F)"
OLD_DAY="$(date -d '10 days ago' +%F)"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

printf '{"ok":true}\n' > "${TMP_DIR}/if_flow-${TODAY}.jsonl"
printf '{"ok":true}\n' > "${TMP_DIR}/if_flow-${YESTERDAY}.jsonl"
printf '{"ok":true}\n' > "${TMP_DIR}/if_flow-${OLD_DAY}.jsonl"
printf '{"old":true}\n' | gzip -c > "${TMP_DIR}/if_flow-${OLD_DAY}.jsonl.gz"

bash "${ROOT_DIR}/scripts/if_flow_archive.sh" --base-path "${BASE_PATH}" --retention-days 7 >/tmp/if_flow_archive_test.log

test -f "${TMP_DIR}/if_flow-${TODAY}.jsonl"
test -f "${TMP_DIR}/if_flow-${YESTERDAY}.jsonl.gz"
test ! -f "${TMP_DIR}/if_flow-${YESTERDAY}.jsonl"
test ! -f "${TMP_DIR}/if_flow-${OLD_DAY}.jsonl"
test ! -f "${TMP_DIR}/if_flow-${OLD_DAY}.jsonl.gz"

echo "archive smoke passed"
