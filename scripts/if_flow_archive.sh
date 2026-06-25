#!/usr/bin/env bash
set -euo pipefail

BASE_PATH=""
RETENTION_DAYS=7
DRY_RUN=0

usage() {
    cat <<'EOF'
usage: if_flow_archive.sh --base-path PATH [--retention-days N] [--dry-run]

Examples:
  if_flow_archive.sh --base-path /opt/if_flow/if_flow.jsonl
  if_flow_archive.sh --base-path /opt/if_flow/if_flow.jsonl --retention-days 14
EOF
}

log() {
    printf '[archive] %s\n' "$*"
}

run_cmd() {
    if (( DRY_RUN )); then
        printf '[archive] dry-run:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-path)
            BASE_PATH="${2:-}"
            shift 2
            ;;
        --retention-days)
            RETENTION_DAYS="${2:-}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "${BASE_PATH}" ]]; then
    echo "--base-path is required" >&2
    usage >&2
    exit 1
fi

if ! [[ "${RETENTION_DAYS}" =~ ^[0-9]+$ ]]; then
    echo "--retention-days must be a non-negative integer" >&2
    exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASE_PATH}")" && pwd)"
BASE_NAME="$(basename "${BASE_PATH}")"
TODAY="$(date +%F)"

STEM="${BASE_NAME}"
EXT=""
if [[ "${BASE_NAME}" == *.* ]]; then
    STEM="${BASE_NAME%.*}"
    EXT=".${BASE_NAME##*.}"
fi

log "base_dir=${BASE_DIR}"
log "base_name=${BASE_NAME}"
log "retention_days=${RETENTION_DAYS}"

shopt -s nullglob
for path in "${BASE_DIR}/${STEM}-"*"${EXT}"; do
    name="$(basename "${path}")"
    if [[ "${name}" =~ ^${STEM}-([0-9]{4}-[0-9]{2}-[0-9]{2})${EXT}$ ]]; then
        day="${BASH_REMATCH[1]}"
        if [[ "${day}" == "${TODAY}" ]]; then
            continue
        fi
        log "compressing ${name}"
        run_cmd gzip -f "${path}"
    fi
done

cutoff_epoch="$(date -d "${TODAY} - ${RETENTION_DAYS} days" +%s)"
for path in "${BASE_DIR}/${STEM}-"*"${EXT}.gz"; do
    name="$(basename "${path}")"
    if [[ "${name}" =~ ^${STEM}-([0-9]{4}-[0-9]{2}-[0-9]{2})${EXT}\.gz$ ]]; then
        day="${BASH_REMATCH[1]}"
        day_epoch="$(date -d "${day}" +%s)"
        if (( day_epoch < cutoff_epoch )); then
            log "deleting expired archive ${name}"
            run_cmd rm -f "${path}"
        fi
    fi
done

log "done"
