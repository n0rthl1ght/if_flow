#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <iface> [seconds]" >&2
    exit 1
fi

IFACE="$1"
DURATION="${2:-15}"
OUT_BASE="/tmp/if_flow_live.jsonl"

echo "running live smoke test on iface=${IFACE} for ${DURATION}s"
echo "no capture filter is applied; the agent will try to observe all TCP/UDP traffic on the interface"
echo "output base: ${OUT_BASE}"

timeout "${DURATION}" ./if_flow -i "${IFACE}" --json-path "${OUT_BASE}" || true

echo "done"
