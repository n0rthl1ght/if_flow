# clickhouse_uploader

`clickhouse_uploader` is a companion component for `if_flow`. The agent itself stays focused on packet capture and local JSONL export, while the uploader reads those JSONL files incrementally and ships them to ClickHouse over HTTP using `JSONEachRow`.

## What is included

- `if_flow_clickhouse_uploader.py` - stateful uploader
- `schema.sql` - ClickHouse table schema with built-in TTL
- `docker-compose.yml` - optional local stack for ClickHouse, Superset, Grafana, Redis
- `.env.example` - Docker stack environment template
- `if_flow-clickhouse.env.example` - local uploader environment template
- `grafana/` - provisioning files, starter SQL, importable dashboard
- `superset/` - starter views and SQL queries

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
- Superset
- Grafana
- Redis for Superset cache/results

Quick start:

```bash
cd clickhouse_uploader
cp .env.example .env
docker compose up -d --build
```

Default ports can be customized through `.env`:

- ClickHouse HTTP: `${CLICKHOUSE_HTTP_PORT}`
- ClickHouse native: `${CLICKHOUSE_NATIVE_PORT}`
- Superset UI: `${SUPERSET_PORT}`
- Grafana UI: `${GRAFANA_PORT}`

All credentials are now controlled through `.env` placeholders rather than hardcoded values in the compose file.

## Choosing Grafana vs Superset

For `if_flow`, the safest default choice is `Grafana`.

Choose `Grafana` when:

- you need production dashboards
- traffic volume is already large or expected to grow quickly
- the main use case is time-series monitoring
- you want fast top-talker and traffic-by-direction panels

Choose `Superset` when:

- you need exploratory analysis
- you want to write ad-hoc SQL and create custom analytical views
- the workflow is closer to investigation than to permanent monitoring

Recommended operating model:

- `Grafana` for day-to-day monitoring
- `Superset` for deeper analytical work

If you are unsure, start with `Grafana` first and add `Superset` later only if the team truly needs SQL-first exploration.

## Grafana

Grafana provisioning is included:

- datasource template: [grafana/provisioning/datasources/clickhouse.yaml](grafana/provisioning/datasources/clickhouse.yaml)
- dashboard provisioning: [grafana/provisioning/dashboards/default.yaml](grafana/provisioning/dashboards/default.yaml)
- importable dashboard: [grafana/if_flow_dashboard.json](grafana/if_flow_dashboard.json)
- SQL query set:
  - [grafana/queries/traffic_by_minute.sql](grafana/queries/traffic_by_minute.sql)
  - [grafana/queries/traffic_by_direction.sql](grafana/queries/traffic_by_direction.sql)
  - [grafana/queries/top_classes.sql](grafana/queries/top_classes.sql)
  - [grafana/queries/top_pairs.sql](grafana/queries/top_pairs.sql)
  - [grafana/queries/top_processes.sql](grafana/queries/top_processes.sql)
  - [grafana/queries/tcp_without_syn.sql](grafana/queries/tcp_without_syn.sql)

Grafana is the recommended default UI for large traffic volumes because it handles time-series and top-N panels more predictably than the current Superset setup.

## Superset

Superset starter assets:

- config: [superset/superset_config.py](superset/superset_config.py)
- views: [superset/if_flow_views.sql](superset/if_flow_views.sql)
- dashboard queries: [superset/dashboard_queries.sql](superset/dashboard_queries.sql)
- investigation queries: [superset/investigation_queries.sql](superset/investigation_queries.sql)
- widget notes: [superset/WIDGETS.md](superset/WIDGETS.md)

To load the starter views after the stack is up:

```bash
cd clickhouse_uploader
docker compose exec -T clickhouse clickhouse-client \
  --user "${CLICKHOUSE_USER}" \
  --password "${CLICKHOUSE_PASSWORD}" \
  --database "${CLICKHOUSE_DB}" < ./superset/if_flow_views.sql
```

When connecting ClickHouse in Superset, use your actual values from `.env`, for example:

```text
clickhousedb://<CLICKHOUSE_USER>:<CLICKHOUSE_PASSWORD>@clickhouse:8123/<CLICKHOUSE_DB>
```

## systemd deployment

For systemd installations, use the dedicated template from:

- [../deploy/systemd/if_flow-clickhouse.env.example](../deploy/systemd/if_flow-clickhouse.env.example)

That template is intended for `/opt/if_flow` style deployment and differs from the local project template.

## Retention

ClickHouse-side retention is already defined in [schema.sql](schema.sql) through table TTL. Local file retention and compression remain separate and are handled by the main project archiver script.
