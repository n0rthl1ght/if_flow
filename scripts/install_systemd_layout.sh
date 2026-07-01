#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/opt/if_flow}"
ETC_DIR="${ETC_DIR:-/opt/if_flow/deploy/systemd}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
INSTALL_ENV=1
RELOAD_SYSTEMD=0
INSTALL_BUILD_DEPS=0
BUILD_MODE=""
DEPLOY_MODE="host"
WITH_WAZUH=0

usage() {
    cat <<'EOF'
usage: install_systemd_layout.sh [options]

Options:
  --mode MODE          Deployment mode: host or server (default: host)
  --prefix PATH         Install project files under PATH (default: /opt/if_flow)
  --etc-dir PATH        Install env file under PATH (default: /opt/if_flow/deploy/systemd)
  --systemd-dir PATH    Install unit files under PATH (default: /etc/systemd/system)
  --install-build-deps  Install compiler/runtime dependencies for this host
  --build-userspace     Build only the userspace binary before install
  --build-all           Build userspace + BPF object before install
  --with-wazuh          Include optional Wazuh bridge files and service
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

same_path() {
    local left="$1"
    local right="$2"
    local left_real=""
    local right_real=""

    if ! command -v readlink >/dev/null 2>&1; then
        return 1
    fi

    left_real="$(readlink -f "${left}" 2>/dev/null || true)"
    right_real="$(readlink -f "${right}" 2>/dev/null || true)"

    [[ -n "${left_real}" && -n "${right_real}" && "${left_real}" == "${right_real}" ]]
}

require_root_for_mutation() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "this operation requires root privileges" >&2
        exit 1
    fi
}

install_build_deps() {
    require_root_for_mutation
    if command -v apt-get >/dev/null 2>&1; then
        log "installing build dependencies via apt-get"
        apt-get update
        apt-get install -y \
            build-essential \
            clang \
            llvm \
            bpftool \
            libbpf-dev \
            libpcap-dev \
            libelf-dev \
            zlib1g-dev \
            pkg-config \
            python3 \
            make
        return
    fi

    if command -v dnf >/dev/null 2>&1; then
        log "installing build dependencies via dnf"
        dnf install -y \
            gcc \
            make \
            clang \
            llvm \
            bpftool \
            libbpf-devel \
            libpcap-devel \
            elfutils-libelf-devel \
            zlib-devel \
            pkgconf-pkg-config \
            python3
        return
    fi

    echo "unsupported package manager: expected apt-get or dnf" >&2
    exit 1
}

build_project() {
    local target="$1"
    log "building target=${target}"
    make -C "${PROJECT_DIR}" "${target}"
}

validate_mode() {
    case "${DEPLOY_MODE}" in
        host|server)
            ;;
        *)
            echo "invalid --mode '${DEPLOY_MODE}': expected host or server" >&2
            exit 1
            ;;
    esac
}

copy_file() {
    local src="$1"
    local dst="$2"
    if same_path "${src}" "${dst}"; then
        log "skipping identical file ${dst}"
        return 0
    fi
    install -D -m 0644 "${src}" "${dst}"
}

copy_exec() {
    local src="$1"
    local dst="$2"
    if same_path "${src}" "${dst}"; then
        log "skipping identical executable ${dst}"
        return 0
    fi
    install -D -m 0755 "${src}" "${dst}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            DEPLOY_MODE="${2:-}"
            shift 2
            ;;
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
        --install-build-deps)
            INSTALL_BUILD_DEPS=1
            shift
            ;;
        --build-userspace)
            BUILD_MODE="userspace"
            shift
            ;;
        --build-all)
            BUILD_MODE="all"
            shift
            ;;
        --with-wazuh)
            WITH_WAZUH=1
            shift
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

validate_mode

TARGET_PREFIX="${DESTDIR}${PREFIX}"
TARGET_ETC_DIR="${DESTDIR}${ETC_DIR}"
TARGET_SYSTEMD_DIR="${DESTDIR}${SYSTEMD_DIR}"

log "project_dir=${PROJECT_DIR}"
log "deploy_mode=${DEPLOY_MODE}"
log "prefix=${TARGET_PREFIX}"
log "etc_dir=${TARGET_ETC_DIR}"
log "systemd_dir=${TARGET_SYSTEMD_DIR}"

if (( INSTALL_BUILD_DEPS )); then
    install_build_deps
fi

case "${BUILD_MODE}" in
    userspace)
        build_project if_flow
        ;;
    all)
        build_project all
        ;;
esac

if [[ "${DEPLOY_MODE}" == "host" && ! -x "${PROJECT_DIR}/if_flow" ]]; then
    echo "missing built binary: ${PROJECT_DIR}/if_flow" >&2
    echo "hint: run 'make if_flow', 'make', or use --build-userspace/--build-all" >&2
    exit 1
fi

copy_file "${PROJECT_DIR}/clickhouse_uploader/schema.sql" "${TARGET_PREFIX}/clickhouse_uploader/schema.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/README.md" "${TARGET_PREFIX}/clickhouse_uploader/README.md"
copy_file "${PROJECT_DIR}/clickhouse_uploader/docker-compose.yml" "${TARGET_PREFIX}/clickhouse_uploader/docker-compose.yml"
copy_file "${PROJECT_DIR}/clickhouse_uploader/.env.example" "${TARGET_PREFIX}/clickhouse_uploader/.env.example"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/provisioning/datasources/clickhouse.yaml" "${TARGET_PREFIX}/clickhouse_uploader/grafana/provisioning/datasources/clickhouse.yaml"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/provisioning/dashboards/default.yaml" "${TARGET_PREFIX}/clickhouse_uploader/grafana/provisioning/dashboards/default.yaml"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/README.md" "${TARGET_PREFIX}/clickhouse_uploader/grafana/README.md"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/if_flow_dashboard.json" "${TARGET_PREFIX}/clickhouse_uploader/grafana/if_flow_dashboard.json"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/traffic_by_minute.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/traffic_by_minute.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/traffic_by_direction.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/traffic_by_direction.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/top_classes.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/top_classes.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/class_breakdown.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/class_breakdown.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/top_pairs.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/top_pairs.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/top_processes.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/top_processes.sql"
copy_file "${PROJECT_DIR}/clickhouse_uploader/grafana/queries/tcp_without_syn.sql" "${TARGET_PREFIX}/clickhouse_uploader/grafana/queries/tcp_without_syn.sql"
install -d -m 0755 \
    "${TARGET_PREFIX}/clickhouse_uploader/storage/clickhouse/data" \
    "${TARGET_PREFIX}/clickhouse_uploader/storage/clickhouse/logs" \
    "${TARGET_PREFIX}/clickhouse_uploader/storage/grafana/data"

if [[ "${DEPLOY_MODE}" == "host" ]]; then
    copy_exec "${PROJECT_DIR}/if_flow" "${TARGET_PREFIX}/if_flow"
    copy_exec "${PROJECT_DIR}/scripts/run_if_flow.sh" "${TARGET_PREFIX}/scripts/run_if_flow.sh"
    copy_exec "${PROJECT_DIR}/scripts/if_flow_archive.sh" "${TARGET_PREFIX}/scripts/if_flow_archive.sh"
    copy_exec "${PROJECT_DIR}/clickhouse_uploader/if_flow_clickhouse_uploader.py" "${TARGET_PREFIX}/clickhouse_uploader/if_flow_clickhouse_uploader.py"
    copy_exec "${PROJECT_DIR}/clickhouse_uploader/run_uploader_once.sh" "${TARGET_PREFIX}/clickhouse_uploader/run_uploader_once.sh"
    copy_exec "${PROJECT_DIR}/clickhouse_uploader/run_uploader_loop.sh" "${TARGET_PREFIX}/clickhouse_uploader/run_uploader_loop.sh"
    copy_file "${PROJECT_DIR}/clickhouse_uploader/if_flow-clickhouse.env.example" "${TARGET_PREFIX}/clickhouse_uploader/if_flow-clickhouse.env.example"

    if [[ -f "${PROJECT_DIR}/bpf/if_flow.bpf.o" ]]; then
        copy_file "${PROJECT_DIR}/bpf/if_flow.bpf.o" "${TARGET_PREFIX}/bpf/if_flow.bpf.o"
    fi

    copy_file "${PROJECT_DIR}/deploy/systemd/if_flow.service" "${TARGET_SYSTEMD_DIR}/if_flow.service"
    copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-archive.service" "${TARGET_SYSTEMD_DIR}/if_flow-archive.service"
    copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-archive.timer" "${TARGET_SYSTEMD_DIR}/if_flow-archive.timer"
    copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-clickhouse-uploader.service" "${TARGET_SYSTEMD_DIR}/if_flow-clickhouse-uploader.service"

fi

if (( WITH_WAZUH )); then
    copy_exec "${PROJECT_DIR}/wazuh_integration/if_flow_wazuh_bridge.py" "${TARGET_PREFIX}/wazuh_integration/if_flow_wazuh_bridge.py"
    copy_file "${PROJECT_DIR}/wazuh_integration/README.md" "${TARGET_PREFIX}/wazuh_integration/README.md"
    copy_exec "${PROJECT_DIR}/wazuh_integration/run_wazuh_bridge_once.sh" "${TARGET_PREFIX}/wazuh_integration/run_wazuh_bridge_once.sh"
    copy_exec "${PROJECT_DIR}/wazuh_integration/run_wazuh_bridge_loop.sh" "${TARGET_PREFIX}/wazuh_integration/run_wazuh_bridge_loop.sh"
    copy_file "${PROJECT_DIR}/wazuh_integration/if_flow-wazuh.env.example" "${TARGET_PREFIX}/wazuh_integration/if_flow-wazuh.env.example"
    copy_file "${PROJECT_DIR}/wazuh_integration/wazuh-localfile.xml.example" "${TARGET_PREFIX}/wazuh_integration/wazuh-localfile.xml.example"
    copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-wazuh-bridge.service" "${TARGET_SYSTEMD_DIR}/if_flow-wazuh-bridge.service"
fi

if (( INSTALL_ENV )) && [[ "${DEPLOY_MODE}" == "host" ]]; then
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

if (( INSTALL_ENV )) && (( WITH_WAZUH )); then
    if [[ ! -f "${TARGET_ETC_DIR}/if_flow-wazuh.env" ]]; then
        copy_file "${PROJECT_DIR}/deploy/systemd/if_flow-wazuh.env.example" "${TARGET_ETC_DIR}/if_flow-wazuh.env"
        log "installed wazuh env template to ${TARGET_ETC_DIR}/if_flow-wazuh.env"
    else
        log "wazuh env file already exists, keeping ${TARGET_ETC_DIR}/if_flow-wazuh.env"
    fi
fi

if (( RELOAD_SYSTEMD )) && [[ -z "${DESTDIR}" ]] && [[ "${DEPLOY_MODE}" == "host" ]]; then
    log "running systemctl daemon-reload"
    systemctl daemon-reload
fi

log "done"
