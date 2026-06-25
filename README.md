# if_flow

Host-level network traffic accounting agent written in C. It captures TCP/UDP traffic, aggregates it in memory, enriches flows with optional process and application metadata, and exports minute-based records without storing raw packets.

Documentation:

- [README.ru.md](README.ru.md) - detailed documentation in Russian
- [README.en.md](README.en.md) - detailed documentation in English
- [clickhouse_uploader/README.md](clickhouse_uploader/README.md) - ClickHouse uploader, Docker stack, Grafana and Superset

Visualization choice:

| Need | Recommended tool |
| --- | --- |
| Production monitoring, time-series, large traffic volume | `Grafana` |
| Ad-hoc analysis, SQL exploration, investigations | `Superset` |
| Only one UI and not sure where to start | `Grafana` |

Quick start:

```bash
make
./if_flow --selftest
./if_flow -i any --json-path ./if_flow.jsonl
```

For ClickHouse upload and dashboards, continue with [clickhouse_uploader/README.md](clickhouse_uploader/README.md).
