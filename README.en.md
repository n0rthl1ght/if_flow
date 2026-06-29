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

## Current limits

- only `TCP/UDP` are tracked today
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

- `/opt/of_flow/deploy/systemd/if_flow.env`
- `/opt/of_flow/deploy/systemd/if_flow-clickhouse.env`

Install:

```bash
sudo make install-systemd
sudo systemctl enable --now if_flow.service
sudo systemctl enable --now if_flow-archive.timer
```

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
