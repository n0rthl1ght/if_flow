#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/opt/if_flow}"
ETC_DIR="${ETC_DIR:-/etc/if_flow}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
INSTALL_ENV=1
RELOAD_SYSTEMD=0

usage() {
    cat <<'EOF'
usage: install_systemd_layout.sh [options]

Options:
  --prefix PATH         Install project files under PATH (default: /opt/if_flow)
  --etc-dir PATH        Install env file under PATH (default: /etc/if_flow)
  --systemd-dir PATH    Install unit files under PATH (default: /etc/systemd/system)
  --no-env              Do not install the example env file
  --reload-systemd      Run systemctl daemon-reload after copying units
  -h, --help            Show this help

Environment:
  DESTDIR               Optional staging root for packaging/testing
EOF
}

log() {
    printf '[install] %s\n' "$*"
}

copy_file() {
    local src="$1"
    local dst="$2"
    install -D -m 0644 "${src}" "${dst}"
}

copy_exec() {
    local src="$1"
    local dst="$2"
    install -D -m 0755 "${src}" "${dst}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="${2:-}"
            shift 2
            ;;
        --etc-dir)
            ETC_DIR="${2:-}"
            shift 2
            ;;
        --systemd-dir)
            SYSTEMD_DIR="${2:-}"
            shift 2
            ;;
        --no-env)
            INSTALL_ENV=0
            shift
            ;;
        --reload-systemd)
            RELOAD_SYSTEMD=1
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

TARGET_PREFIX="${DESTDIR}${PREFIX}"
TARGET_ETC_DIR="${DESTDIR}${ETC_DIR}"
TARGET_SYSTEMD_DIR="${DESTDIR}${SYSTEMD_DIR}"

log "project_dir=${PROJECT_DIR}"
log "prefix=${TARGET_PREFIX}"
log "etc_dir=${TARGET_ETC_DIR}"
log "systemd_dir=${TARGET_SYSTEMD_DIR}"

copy_exec "${PROJECT_DIR}/if_flow" "${TARGET_PREFIX}/if_flow"
copy_exec "${PROJECT_DIR}/scripts/run_if_flow.sh" "${TARGET_PREFIX}/scripts/run_if_flow.sh"
copy_exec "${PROJECT_DIR}/scripts/if_flow_archive.sh" "${TARGET_PREFIX}/scripts/if_flow_archive.sh"
copy_exec "${PROJECT_DIR}/clickhouse_uploader/if_flow_clickhouse_uploader.py" "${TARGET_PREFIX}/clickhouse_uploader/if_flow_clickhouse_uploader.py"
copy_file "${PROJECT_DIR}/clickhouse_uploader/schema.sql" "${TARGET_PREFIX}/clickhouse_uploader/schema.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/README.md" "${TARGET_PREFIX}/clickhouse_uploader/README.md"
copy_file "${PROJECT_DIR}/clickhouse_uploader/docker-compose.yml" "${TARGET_PREFIX}/clickhouse_uploader/docker-compose.yml"
copy_file "${PROJECT_DIR}/clickhouse_uploader/.env.example" "${TARGET_PREFIX}/clickhouse_uploader/.env.example"
copy_file "${PROJECT_DIR}/clickhouse_uploader/Dockerfile.superset" "${TARGET_PREFIX}/clickhouse_uploader/Dockerfile.superset"
copy_file "${PROJECT_DIR}/clickhouse_uploader/run_uploader_once.sh" "${TARGET_PREFIX}/clickhouse_uploader/run_uploader_once.sh"
copy_file "${PROJECT_DIR}/clickhouse_uploader/run_uploader_loop.sh" "${TARGET_PREFIX}/clickhouse_uploader/run_uploader_loop.sh"
copy_file "${PROJECT_DIR}/clickhouse_uploader/if_flow-clickhouse.env.example" "${TARGET_PREFIX}/clickhouse_uploader/if_flow-clickhouse.env.example"
copy_file "${PROJECT_DIR}/clickhouse_uploader/superset/superset_config.py" "${TARGET_PREFIX}/clickhouse_uploader/superset/superset_config.py"
copy_file "${PROJECT_DIR}/clickhouse_uploader/superset/if_flow_views.sql" "${TARGET_PREFIX}/clickhouse_uploader/superset/if_flow_views.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/superset/dashboard_queries.sql" "${TARGET_PREFIX}/clickhouse_uploader/superset/dashboard_queries.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/superset/investigation_queries.sql" "${TARGET_PREFIX}/clickhouse_uploader/superset/investigation_queries.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/superset/WIDGETS.md" "${TARGET_PREFIX}/clickhouse_uploader/superset/WIDGETS.md"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/provisioning/datasources/clickhouse.yaml" "${TARGET_PREFIX}/clickhouse_uploader/grafana/provisioning/datasources/clickhouse.yaml"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/provisioning/dashboards/default.yaml" "${TARGET_PREFIX}/clickhouse_uploader/grafana/provisioning/dashboards/default.yaml"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/README.md" "${TARGET_PREFIX}/clickhouse_uploader/grafana/README.md"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/if_flow_dashboard.json" "${TARGET_PREFIX}/clickhouse_uploader/grafana/if_flow_dashboard.json"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/traffic_by_minute.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/traffic_by_minute.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/traffic_by_direction.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/traffic_by_direction.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/top_classes.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/top_classes.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/top_pairs.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/top_pairs.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/top_processes.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/top_processes.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/tcp_without_syn.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/tcp_without_syn.sql"

if [[ -f "${PROJECT_DIR}/bpf/if_flow.bpf.o" ]]; then
    copy_file "${PROJECT_DIR}/bpf/if_flow.bpf.o" "${TARGET_PREFIX}/bpf/if_flow.bpf.o"
fi

copy_file "${PROJECT_DIR}/deploy/systemd/if_flow.service" "${TARGET_SYSTEMD_DIR}/if_flow.service"
copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-archive.service" "${TARGET_SYSTEMD_DIR}/if_flow-archive.service"
copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-archive.timer" "${TARGET_SYSTEMD_DIR}/if_flow-archive.timer"
copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-clickhouse-uploader.service" "${TARGET_SYSTEMD_DIR}/if_flow-clickhouse-uploader.service"

if (( INSTALL_ENV )); then
    if [[ ! -f "${TARGET_ETC_DIR}/if_flow.env" ]]; then
        copy_file "${PROJECT_DIR}/deploy/systemd/if_flow.env.example" "${TARGET_ETC_DIR}/if_flow.env"
        log "installed env template to ${TARGET_ETC_DIR}/if_flow.env"
    else
        log "env file already exists, keeping ${TARGET_ETC_DIR}/if_flow.env"
    fi
    if [[ ! -f "${TARGET_ETC_DIR}/if_flow-clickhouse.env" ]]; then
        copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-clickhouse.env.example" "${TARGET_ETC_DIR}/if_flow-clickhouse.env"
        log "installed clickhouse env template to ${TARGET_ETC_DIR}/if_flow-clickhouse.env"
    else
        log "clickhouse env file already exists, keeping ${TARGET_ETC_DIR}/if_flow-clickhouse.env"
    fi
fi

if (( RELOAD_SYSTEMD )) && [[ -z "${DESTDIR}" ]]; then
    log "running systemctl daemon-reload"
    systemctl daemon-reload
fi

log "done"
