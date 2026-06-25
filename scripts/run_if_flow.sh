#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IF_FLOW_BIN="${IF_FLOW_BIN:-${PROJECT_DIR}/if_flow}"
IF_FLOW_INTERFACE="${IF_FLOW_INTERFACE:-any}"
IF_FLOW_JSON_PATH="${IF_FLOW_JSON_PATH:-${PROJECT_DIR}/if_flow.jsonl}"
IF_FLOW_ARGS="${IF_FLOW_ARGS:-}"

cd "${PROJECT_DIR}"
exec /bin/sh -c 'exec "$1" -i "$2" --json-path "$3" $4' _ \
    "${IF_FLOW_BIN}" "${IF_FLOW_INTERFACE}" "${IF_FLOW_JSON_PATH}" "${IF_FLOW_ARGS}"
