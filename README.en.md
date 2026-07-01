# if_flow

`if_flow` is a host-level network traffic accounting agent written in C. It is designed to keep resource usage low, avoid raw packet storage, and produce minute-based flow records that can be exported locally or uploaded to ClickHouse.

## What the project does

- captures traffic with `libpcap`
- aggregates traffic by `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`
- keeps aggregation in memory per minute bucket
- emits streaming `update` records for active flows
- emits `final` records when a minute bucket closes
- determines `in`, `out`, `internal`, and `transit` directions
- enriches flows with `eBPF`-based process attribution and `/proc` fallback
- extracts `TLS SNI` and `HTTP Host` when available
- classifies traffic into practical operational classes
- writes local `JSONL`
- uploads records to `ClickHouse` using a separate uploader
- includes systemd units plus Grafana assets

The current prototype covers:

- `host`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `proto`
- `packets`
- `bytes`, `bytes_human`
- `connections`
- `minute_ts`, `minute_iso`
- `record_type=update/final`

## High-level architecture

1. `libpcap` receives a packet.
2. The agent normalizes L2/L3/L4 metadata into a canonical `5-tuple`.
3. If payload is visible, it tries to extract `TLS SNI` and `HTTP Host`.
4. Flow-to-process attribution is attempted in this order:
   - `eBPF` cache
   - `/proc` snapshot fallback
5. The in-memory flow table updates counters for the current minute bucket.
6. Active flows are emitted as `update` records.
7. Older minute buckets are emitted as `final` records and removed from memory.

## Repository structure

- `src/main.c` - main loop, packet handling, classification, emission
- `src/flow_table.c` - in-memory aggregation table
- `src/ebpf_tracker.c` - eBPF attribution cache
- `src/resolver.c` - `/proc` fallback resolver
- `src/parser.c` - lightweight TLS/HTTP parsing
- `src/writer_jsonl.c` - JSONL output and rotation
- `src/config.c` - CLI parsing and defaults
- `bpf/if_flow.bpf.c` - eBPF programs
- `clickhouse_uploader/` - uploader, schema, Docker stack, Grafana
- `deploy/systemd/` - systemd units and environment templates
- `scripts/` - helper scripts
- `tests/` - self-tests and smoke tests

## Build requirements

Install:

- `clang`
- `bpftool`
- `libbpf` headers/dev package
- `libpcap` headers/dev package
- `libelf` / `zlib` dev package
- `pkg-config`

Examples:

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential clang llvm bpftool libbpf-dev libpcap-dev libelf-dev zlib1g-dev pkg-config

# RHEL / Rocky / Alma / Fedora
sudo dnf install -y clang llvm bpftool libbpf-devel libpcap-devel elfutils-libelf-devel zlib-devel pkgconf-pkg-config
```

Build:

```bash
make
```

If you see `bpf/bpf_core_read.h file not found`, the host is usually missing `libbpf-dev` or `libbpf-devel`.

## Validation

Synthetic self-test:

```bash
./if_flow --selftest
```

Project tests:

```bash
make test
```

## Running

Minimal live run:

```bash
./if_flow -i any --json-path ./if_flow.jsonl
```

Recommended practical variant:

```bash
./if_flow -i any --datapath --stream-flush-sec 1 --json-max-file-size-mb 256 --json-path ./if_flow.jsonl
```

Useful options:

- `--no-identity-fields`
- `--no-ebpf`
- `--no-datapath`
- `--stream-flush-sec N`
- `--json-max-file-size-mb N`

## Output fields

Core fields:

- `record_type`
- `host`
- `iface`
- `minute_ts`
- `minute_iso`
- `proto`
- `class`
- `direction`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `packets`, `bytes`, `bytes_human`
- `connections`
- `connections_effective`
- `connection_inferred`
- `tcp_seen_without_syn`
- `first_seen_iso`, `last_seen_iso`

Optional identity fields:

- `pid`
- `attr_source`
- `process`
- `cmdline`
- `workload`

Additional enrichment:

- `sni`
- `host_name`

## Classes and Ports

The full `class -> ports` map is available in a separate document:

- [docs/PORT_CLASSES.en.md](docs/PORT_CLASSES.en.md)

That file also captures the current heuristics, priorities, active infrastructure port mappings, and `ICMP/ICMPv6` classes derived from `type/code`.

## Current limits

- `src_port` and `dst_port` are available for `TCP`, `UDP`, and `SCTP`
- for `ICMP/ICMPv6`, `GRE`, `ESP`, `AH`, `OSPF`, `VRRP`, `IGMP`, and `PIM`, both ports are set to `0`, and the class is derived from the protocol number or `type/code`
- `connections` are intentionally simplified in the current version
- midstream TCP may miss the opening `SYN`, so soft flags are exposed
- direction is host-relative
- payload is never persisted; it is only inspected briefly for enrichment

## systemd

Ready-to-use files are available in [deploy/systemd](deploy/systemd):

- [if_flow.service](deploy/systemd/if_flow.service)
- [if_flow-archive.service](deploy/systemd/if_flow-archive.service)
- [if_flow-archive.timer](deploy/systemd/if_flow-archive.timer)
- [if_flow-clickhouse-uploader.service](deploy/systemd/if_flow-clickhouse-uploader.service)
- [if_flow.env.example](deploy/systemd/if_flow.env.example)
- [if_flow-clickhouse.env.example](deploy/systemd/if_flow-clickhouse.env.example)

By default, the unit files expect environment files here:

- `/opt/if_flow/deploy/systemd/if_flow.env`
- `/opt/if_flow/deploy/systemd/if_flow-clickhouse.env`

Install:

```bash
sudo make install-systemd
sudo editor /opt/if_flow/deploy/systemd/if_flow.env
sudo editor /opt/if_flow/deploy/systemd/if_flow-clickhouse.env
sudo systemctl enable --now if_flow.service
sudo systemctl enable --now if_flow-archive.timer
sudo systemctl enable --now if_flow-clickhouse-uploader.service
```

Installation modes:

- `make install-host` - host mode, without Wazuh
- `make bootstrap-host` - fresh host, without Wazuh
- `make install-host-wazuh` - host mode with the Wazuh bridge
- `make bootstrap-host-wazuh` - fresh host with the Wazuh bridge
- `make install-server` - server mode, only ClickHouse/Grafana stack assets
- `make install-server-wazuh` - server mode with the optional Wazuh bridge

Compatible aliases are still available:

- `make install-systemd` -> `make install-host`
- `make bootstrap-systemd` -> `make bootstrap-host`
- `make install-systemd-wazuh` -> `make install-host-wazuh`
- `make bootstrap-systemd-wazuh` -> `make bootstrap-host-wazuh`

Command matrix:

| Scenario | Command | What gets installed |
| --- | --- | --- |
| Prepared host | `make install-host` | `if_flow`, uploader, host-side `systemd` units |
| Fresh host | `sudo make bootstrap-host` | dependencies, build output, `if_flow`, uploader, host-side `systemd` units |
| Prepared host + Wazuh | `make install-host-wazuh` | host stack + optional Wazuh bridge |
| Fresh host + Wazuh | `sudo make bootstrap-host-wazuh` | dependencies, build output, host stack + optional Wazuh bridge |
| Server | `make install-server` | `ClickHouse/Grafana` assets, dashboards, queries, compose files, local storage directories |
| Server + Wazuh | `make install-server-wazuh` | server assets, local storage directories + optional Wazuh bridge |

Bootstrap mode for a fresh host:

```bash
sudo make bootstrap-host
```

That mode:

- installs build/runtime dependencies through `apt-get` or `dnf`
- builds `if_flow` and `bpf/if_flow.bpf.o`
- installs files into `/opt/if_flow`
- copies unit files into `/etc/systemd/system`
- runs `systemctl daemon-reload`

The Wazuh bridge is not installed by default. It is always optional and is enabled only through dedicated commands:

```bash
make install-host-wazuh
sudo make bootstrap-host-wazuh
make install-server-wazuh
```

Practical host deployment flow:

1. On a prepared host: run `make` and then `sudo make install-host`
2. On a fresh host: run `sudo make bootstrap-host`
3. Fill in the env files under `/opt/if_flow/deploy/systemd/`
4. Start `if_flow.service`
5. Enable `if_flow-clickhouse-uploader.service` when ClickHouse upload is needed

Practical server deployment flow:

1. Install server assets with `sudo make install-server`
2. Change into `/opt/if_flow/clickhouse_uploader`
3. Copy `.env.example` to `.env`
4. Verify that local storage directories exist:
   - `/opt/if_flow/clickhouse_uploader/storage/clickhouse/data`
   - `/opt/if_flow/clickhouse_uploader/storage/clickhouse/logs`
   - `/opt/if_flow/clickhouse_uploader/storage/grafana/data`
5. Start the Docker stack with `docker compose up -d`

By default, the bundled Docker stack uses host-side bind mounts instead of Docker named volumes, so ClickHouse and Grafana data remain in the project directory next to `docker-compose.yml`.
3. prepare `.env`
4. run `docker compose up -d --build`

If the server should run only the Wazuh alerting bridge:

1. Run `make install-server-wazuh`
2. fill in `/opt/if_flow/deploy/systemd/if_flow-wazuh.env`
3. enable `if_flow-wazuh-bridge.service`

`if_flow-clickhouse-uploader.service` now launches the same wrapper script used by the manual loop runner and reads the explicit env file `/opt/if_flow/deploy/systemd/if_flow-clickhouse.env`. This keeps manual and systemd behavior aligned.

## Archiving

The helper script [scripts/if_flow_archive.sh](scripts/if_flow_archive.sh):

- keeps the current day untouched
- compresses older `*.jsonl` files into `*.jsonl.gz`
- removes archives older than the configured retention period

Example:

```bash
bash ./scripts/if_flow_archive.sh --base-path /opt/if_flow/if_flow.jsonl --retention-days 7
```

## ClickHouse and Grafana

Uploader and visualization assets live in:

- [clickhouse_uploader/README.md](clickhouse_uploader/README.md)

That directory contains:

- ClickHouse uploader
- schema with TTL
- Docker Compose stack
- Grafana provisioning
- starter SQL and dashboards for Grafana

### Why Grafana is the default UI here

For `if_flow`, `Grafana` is the default and recommended visualization layer.

It is the best fit when:

- you need the main production dashboard
- the dataset is already large or expected to grow quickly
- minute-based time-series monitoring is the priority
- you want fast `top N` panels for `src_ip`, `dst_ip`, `class`, or `process`
- the main goal is continuous operational monitoring

If you only want one UI, `Grafana` is usually the correct starting point for `if_flow`.
