#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${IF_FLOW_CLICKHOUSE_ENV:-${SCRIPT_DIR}/if_flow-clickhouse.env}"
EXAMPLE_ENV_FILE="${SCRIPT_DIR}/if_flow-clickhouse.env.example"

if [[ -f "${ENV_FILE}" ]]; then
    set -a
    . "${ENV_FILE}"
    set +a
elif [[ -f "${EXAMPLE_ENV_FILE}" ]]; then
    set -a
    . "${EXAMPLE_ENV_FILE}"
    set +a
fi

exec python3 "${SCRIPT_DIR}/if_flow_clickhouse_uploader.py" "$@"
