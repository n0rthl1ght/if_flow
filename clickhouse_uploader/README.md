# clickhouse_uploader

`clickhouse_uploader` is a companion component for `if_flow`. The agent itself stays focused on packet capture and local JSONL export, while the uploader reads those JSONL files incrementally and ships them to ClickHouse over HTTP using `JSONEachRow`.

## What is included

- `if_flow_clickhouse_uploader.py` - stateful uploader
- `schema.sql` - ClickHouse table schema with built-in TTL
- `docker-compose.yml` - optional local stack for ClickHouse and Grafana
- `.env.example` - Docker stack environment template
- `if_flow-clickhouse.env.example` - local uploader environment template
- `grafana/` - provisioning files, starter SQL, importable dashboard

## Uploader behavior

The uploader:

- scans daily JSONL files and size-rotated chunks
- keeps file offsets in a state file
- resumes from the previous offset after restart
- validates every line as JSON before sending
- sends batches to ClickHouse via HTTP
- retries with backoff on transient delivery errors
- can delete or truncate fully uploaded files when explicitly enabled

By default, the uploader table in [schema.sql](schema.sql) uses a `7 day` TTL for data retention in ClickHouse.

## Environment templates

For local helper scripts:

- copy [if_flow-clickhouse.env.example](if_flow-clickhouse.env.example) to `if_flow-clickhouse.env`
- adjust paths, ClickHouse URL, and credentials as needed

For the Docker stack:

- copy [.env.example](.env.example) to `.env`
- replace all placeholder passwords before exposing the stack anywhere outside a local lab

The helper scripts will automatically use `if_flow-clickhouse.env` if it exists, or fall back to `if_flow-clickhouse.env.example`.

## Local quick start

One-shot upload:

```bash
cd clickhouse_uploader
cp if_flow-clickhouse.env.example if_flow-clickhouse.env
bash ./run_uploader_once.sh
```

Dry-run:

```bash
cd clickhouse_uploader
bash ./run_uploader_once.sh --dry-run
```

Loop mode:

```bash
cd clickhouse_uploader
bash ./run_uploader_loop.sh
```

## Cleanup modes

Two cleanup switches are available:

- `IF_FLOW_UPLOADER_DELETE_SENT_ROTATED=1` - remove fully uploaded rotated files and past-day files
- `IF_FLOW_UPLOADER_TRUNCATE_SENT_ACTIVE=1` - truncate the active plain daily file after full upload

Recommended production mode for high-volume hosts:

- enable size rotation in `if_flow`
- use `IF_FLOW_JSON_PATH=/opt/if_flow/if_flow-*.jsonl`
- set `IF_FLOW_UPLOADER_DELETE_SENT_ROTATED=1`
- keep `IF_FLOW_UPLOADER_TRUNCATE_SENT_ACTIVE=0` unless you explicitly want active-file truncation

## Docker stack

The bundled `docker-compose.yml` starts:

- ClickHouse
- Grafana

Quick start:

```bash
cd clickhouse_uploader
cp .env.example .env
docker compose up -d --build
```

Default ports can be customized through `.env`:

- ClickHouse HTTP: `${CLICKHOUSE_HTTP_PORT}`
- ClickHouse native: `${CLICKHOUSE_NATIVE_PORT}`
- Grafana UI: `${GRAFANA_PORT}`

All credentials are now controlled through `.env` placeholders rather than hardcoded values in the compose file.

## Grafana-first visualization

For `if_flow`, `Grafana` is the default and recommended visualization layer.

It is the best fit when:

- traffic volume is already large or expected to grow quickly
- the main use case is minute-based monitoring
- you need stable time-series panels and top talker views
- you want one operational UI without extra analytics stack complexity

Note:

- the shipped `if_flow_dashboard.json` is intentionally minimal and does not define dashboard variables out of the box
- recommended variables such as `host`, `direction`, `class`, `process`, `src_ip`, and `dst_ip` are documented in `grafana/README.md` as suggested next-step improvements

## Grafana

Grafana provisioning is included:

- datasource template: [grafana/provisioning/datasources/clickhouse.yaml](grafana/provisioning/datasources/clickhouse.yaml)
- dashboard provisioning: [grafana/provisioning/dashboards/default.yaml](grafana/provisioning/dashboards/default.yaml)
- importable dashboard: [grafana/if_flow_dashboard.json](grafana/if_flow_dashboard.json)
- SQL query set:
  - [grafana/queries/traffic_by_minute.sql](grafana/queries/traffic_by_minute.sql)
  - [grafana/queries/traffic_by_direction.sql](grafana/queries/traffic_by_direction.sql)
  - [grafana/queries/top_classes.sql](grafana/queries/top_classes.sql)
  - [grafana/queries/class_breakdown.sql](grafana/queries/class_breakdown.sql)
  - [grafana/queries/top_pairs.sql](grafana/queries/top_pairs.sql)
  - [grafana/queries/top_pairs_with_alias_switch.sql](grafana/queries/top_pairs_with_alias_switch.sql)
  - [grafana/queries/top_processes.sql](grafana/queries/top_processes.sql)
  - [grafana/queries/tcp_without_syn.sql](grafana/queries/tcp_without_syn.sql)

Grafana is the recommended default UI for large traffic volumes because it handles time-series and top-N panels predictably and keeps the stack simpler.

## Grafana host filters and alias switch

A practical Grafana setup for `if_flow` usually includes:

- `traffic_filter` - a `Query` variable populated from ClickHouse host values
- `name_mode` - a `Custom` variable with values `ip,mapped`

Recommended `traffic_filter` query:

```sql
SELECT DISTINCT host
FROM default.if_flow_final
ORDER BY host
```

Recommended variable behavior:

- `Type`: `Query`
- `Multi-value`: `On`
- `Include All option`: `On`
- default selection: `All`

Typical host filter condition:

```sql
AND (
  '${traffic_filter:raw}' = 'All'
  OR host IN (${traffic_filter:sqlstring})
)
```

Typical name switch behavior:

- `name_mode=ip` - show raw `src_ip` and `dst_ip`
- `name_mode=mapped` - replace matching IPs with aliases from a lookup table

Recommended lookup table:

```sql
CREATE TABLE default.ip_aliases
(
    ip String,
    alias String,
    alias_type LowCardinality(String) DEFAULT 'manual',
    comment String DEFAULT '',
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ip
```

One alias may safely correspond to multiple IP addresses. The lookup is always done by `ip`.

Example alias records:

```sql
INSERT INTO default.ip_aliases (ip, alias, alias_type, comment) VALUES
('212.233.91.139', 'wg-frr-251', 'manual', 'WireGuard router in Moscow'),
('172.18.99.10', 'kube-monitoring', 'manual', 'Monitoring node'),
('176.124.218.78', 'wg-frr-252', 'manual', 'Second WireGuard router'),
('72.56.240.153', 'db-center', 'manual', 'Database endpoint'),
('10.10.10.11', 'kube-monitoring', 'manual', 'Same logical host, second IP');
```

To inspect current alias mappings:

```sql
SELECT ip, alias, alias_type, comment, updated_at
FROM default.ip_aliases
ORDER BY alias, ip;
```

Ready example:

- [grafana/queries/top_pairs_with_alias_switch.sql](grafana/queries/top_pairs_with_alias_switch.sql)

That query demonstrates:

- host filtering through `traffic_filter`
- alias switching through `name_mode`
- fallback to raw IP when no alias is found

## systemd deployment

For systemd installations, use the dedicated template from:

- [../deploy/systemd/if_flow-clickhouse.env.example](../deploy/systemd/if_flow-clickhouse.env.example)

That template is intended for `/opt/if_flow` style deployment and differs from the local project template.

For host-side systemd deployment, the uploader service uses:

- unit: [../deploy/systemd/if_flow-clickhouse-uploader.service](../deploy/systemd/if_flow-clickhouse-uploader.service)
- env: `/opt/if_flow/deploy/systemd/if_flow-clickhouse.env`

Recommended sequence on a traffic source host:

```bash
sudo make install-systemd
sudo editor /opt/if_flow/deploy/systemd/if_flow-clickhouse.env
sudo systemctl enable --now if_flow-clickhouse-uploader.service
```

For a fresh host that still lacks dependencies and a built binary, use:

```bash
sudo make bootstrap-systemd
```

Then fill in `/opt/if_flow/deploy/systemd/if_flow-clickhouse.env` and enable the uploader service.

The systemd unit intentionally starts `run_uploader_loop.sh`, not the Python file directly, so host deployment follows the same execution path as manual loop testing.

## Retention

ClickHouse-side retention is already defined in [schema.sql](schema.sql) through table TTL. Local file retention and compression remain separate and are handled by the main project archiver script.
