# Grafana Panels For if_flow

Ниже стартовый набор panel-ов для Grafana, аналогичный набору для Superset.

Datasource:

- `if_flow_clickhouse`

Рекомендуемые dashboard variables:

- `host`
- `direction`
- `class`
- `process`
- `src_ip`
- `dst_ip`

Рекомендуемый time range по умолчанию:

- `Last 1 hour`

## 1. Общий Трафик По Минутам

- `Panel type`: `Time series`
- `Query`: `traffic_by_minute.sql`
- `Legend`: `{{host}}`
- `Unit`: `bytes`

## 2. Трафик По Направлениям

- `Panel type`: `Time series`
- `Query`: `traffic_by_direction.sql`
- `Legend`: отдельные серии `in`, `out`, `internal`, `transit`
- `Stack series`: `on`
- `Unit`: `bytes`

## 3. Топ Классов По Объему

- `Panel type`: `Bar chart`
- `Query`: `top_classes.sql`
- `X`: `class`
- `Y`: `total_bytes`
- `Unit`: `bytes`

## 4. Топ Src -> Dst Пар

- `Panel type`: `Table`
- `Query`: `top_pairs.sql`

## 5. Топ Процессов По Трафику

- `Panel type`: `Table`
- `Query`: `top_processes.sql`

## 6. TCP Flows Без SYN

- `Panel type`: `Table`
- `Query`: `tcp_without_syn.sql`

## Практика

Для тяжелых panel-ов:

- начинай с `Last 15 minutes` или `Last 1 hour`
- ставь `LIMIT 50` или `LIMIT 100`
- для table panel избегай запроса "за все время"
