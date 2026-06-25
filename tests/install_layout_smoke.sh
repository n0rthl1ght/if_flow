#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/if_flow_install_test.XXXXXX)"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

DESTDIR="${TMP_DIR}" bash "${ROOT_DIR}/scripts/install_systemd_layout.sh" >/tmp/if_flow_install_test.log

test -x "${TMP_DIR}/opt/if_flow/if_flow"
test -x "${TMP_DIR}/opt/if_flow/scripts/run_if_flow.sh"
test -x "${TMP_DIR}/opt/if_flow/scripts/if_flow_archive.sh"
test -x "${TMP_DIR}/opt/if_flow/clickhouse_uploader/if_flow_clickhouse_uploader.py"
test -f "${TMP_DIR}/opt/if_flow/bpf/if_flow.bpf.o"
test -f "${TMP_DIR}/opt/if_flow/clickhouse_uploader/schema.sql"
test -f "${TMP_DIR}/etc/systemd/system/if_flow.service"
test -f "${TMP_DIR}/etc/systemd/system/if_flow-archive.service"
test -f "${TMP_DIR}/etc/systemd/system/if_flow-archive.timer"
test -f "${TMP_DIR}/etc/systemd/system/if_flow-clickhouse-uploader.service"
test -f "${TMP_DIR}/etc/if_flow/if_flow.env"
test -f "${TMP_DIR}/etc/if_flow/if_flow-clickhouse.env"

echo "install layout smoke passed"
