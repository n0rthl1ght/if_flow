# Grafana Panels For if_flow

Below is a starter panel set for Grafana tailored to `if_flow`.

Datasource:

- `if_flow_clickhouse`

Recommended dashboard variables:

- `host`
- `direction`
- `class`
- `process`
- `src_ip`
- `dst_ip`
- `traffic_filter`
- `name_mode`

Important:

- the shipped `if_flow_dashboard.json` does not include pre-created variables
- the list above is the recommended variable set to add as the dashboard evolves
- the dashboard works out of the box without them, but it will not have top-level interactive filters

## Host Traffic Filter

Use the `traffic_filter` variable to switch panels between hosts.

Recommended settings:

- `Type`: `Query`
- `Name`: `traffic_filter`
- `Multi-value`: `On`
- `Include All option`: `On`
- default value: `All`

Query for the host list:

```sql
SELECT DISTINCT host
FROM default.if_flow_final
ORDER BY host
```

Typical filter block to insert into existing queries:

```sql
AND (
  '${traffic_filter:raw}' = 'All'
  OR host IN (${traffic_filter:sqlstring})
)
```

Behavior:

- `All` - shows traffic from every host
- one selected host - panels show only that host's data
- multiple selected hosts - panels show combined data only for the selected set

Recommended default time range:

- `Last 1 hour`

## 1. Total Traffic Per Minute

- `Panel type`: `Time series`
- `Query`: `traffic_by_minute.sql`
- `Legend`: `{{host}}`
- `Unit`: `bytes`

## 2. Traffic By Direction

- `Panel type`: `Time series`
- `Query`: `traffic_by_direction.sql`
- `Legend`: separate series for `in`, `out`, `internal`, `transit`
- `Stack series`: `on`
- `Unit`: `bytes`

## 3. Top Classes By Volume

- `Panel type`: `Bar chart`
- `Query`: `top_classes.sql`
- `X`: `class`
- `Y`: `total_bytes`
- `Unit`: `bytes`

## 4. Top Src -> Dst Pairs

- `Panel type`: `Table`
- `Query`: `top_pairs.sql`

For a setup with a manual alias table and `IP <-> mapped` switching:

- `Query`: `top_pairs_with_alias_switch.sql`
- `Variable traffic_filter`: `Query`, host list from ClickHouse
- `Variable name_mode`: `Custom`, values `ip,mapped`

## 5. Top Processes By Traffic

- `Panel type`: `Table`
- `Query`: `top_processes.sql`
- `Aggregation`: `GROUP BY host, process, workload`

## 6. TCP Flows Without SYN

- `Panel type`: `Table`
- `Query`: `tcp_without_syn.sql`

## 7. Class Breakdown

- `Panel type`: `Table`
- `Query`: `class_breakdown.sql`
- `Purpose`: show all class groups for the selected time range without top-N truncation
- `Columns`: `minute_dt`, `class`, `host`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `direction`, `total_bytes`

## Practical Notes

For heavier panels:

- start with `Last 15 minutes` or `Last 1 hour`
- use `LIMIT 50` or `LIMIT 100`
- avoid "all time" queries for table panels
