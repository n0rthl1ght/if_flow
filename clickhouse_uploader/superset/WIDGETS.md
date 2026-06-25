# Superset Widgets For if_flow

Ниже готовая схема для первого dashboard из 6 виджетов.

Перед началом:

- создай datasets:
  - `default.if_flow_final`
  - `default.if_flow_minute_host`
  - `default.if_flow_top_pairs`
- для datasets с полем `minute_dt` укажи:
  - `Temporal column` = `minute_dt`

## 1. Общий Трафик По Минутам

- `Chart type`: `Time-series Line Chart`
- `Dataset`: `default.if_flow_minute_host`
- `Time column`: `minute_dt`
- `Time grain`: `Minute`
- `Metric`: `SUM(bytes)`
- `Group by`: `host`
- `Sort by`: `minute_dt`

Что показывает:

- общий объем трафика по каждому хосту поминутно

Рекомендуемые настройки:

- `Y axis format`: `Smart Number`
- `Contribution mode`: `off`
- `Show legend`: `on`

Если в UI нет понятного поля для разбиения по сериям, используй кастомный SQL:

```sql
SELECT
    minute_dt,
    host,
    sum(bytes) AS total_bytes
FROM default.if_flow_minute_host
GROUP BY minute_dt, host
ORDER BY minute_dt, host
```

Для чарта:

- time column: `minute_dt`
- metric: `SUM(total_bytes)` или `total_bytes`
- series/dimension: `host`

## 2. Трафик По Направлениям

- `Chart type`: `Time-series Bar Chart`
- `Dataset`: `default.if_flow_minute_host`
- `Time column`: `minute_dt`
- `Time grain`: `Minute`
- `Metric`: `SUM(bytes)`
- `Group by`: `direction`

Что показывает:

- разбивку `in/out/internal/transit` по минутам

Рекомендуемые настройки:

- `Stack series`: `on`
- `Y axis format`: `Smart Number`
- `Show legend`: `on`

Если нужное разбиение неудобно задавать через UI, используй SQL:

```sql
SELECT
    minute_dt,
    direction,
    sum(bytes) AS total_bytes
FROM default.if_flow_minute_host
GROUP BY minute_dt, direction
ORDER BY minute_dt, direction
```

Для чарта:

- time column: `minute_dt`
- metric: `SUM(total_bytes)` или `total_bytes`
- series/dimension: `direction`

## 3. Топ Классов По Объему

- `Chart type`: `Bar Chart`
- `Dataset`: `default.if_flow_final`
- `Dimension`: `class`
- `Metric`: `SUM(bytes)`
- `Sort by metric`: `desc`
- `Row limit`: `20`

Что показывает:

- какие типы трафика дают основной объем

Рекомендуемые настройки:

- `X axis`: `SUM(bytes)`
- `Y axis`: `class`
- `Show values`: `on`

SQL-вариант:

```sql
SELECT
    class,
    sum(bytes) AS total_bytes
FROM default.if_flow_final
GROUP BY class
ORDER BY total_bytes DESC
LIMIT 20
```

## 4. Топ Src -> Dst Пар

- `Chart type`: `Table`
- `Dataset`: `default.if_flow_top_pairs`
- `Columns`:
  - `host`
  - `src_ip`
  - `src_port`
  - `dst_ip`
  - `dst_port`
  - `class`
  - `process`
  - `bytes`
  - `packets`
  - `connections`
- `Sort by`: `bytes desc`
- `Row limit`: `100`

Что показывает:

- основные talking pairs по объему и пакетам

Рекомендуемые настройки:

- включить `Search`
- включить `Server pagination`, если доступно

SQL-вариант:

```sql
SELECT
    host,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    class,
    process,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections) AS total_connections
FROM default.if_flow_top_pairs
GROUP BY
    host,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    class,
    process
ORDER BY total_bytes DESC
LIMIT 100
```

## 5. Топ Процессов По Трафику

- `Chart type`: `Table`
- `Dataset`: `default.if_flow_final`
- `Columns`:
  - `minute_dt`
  - `host`
  - `process`
  - `workload`
  - `src_ip`
  - `dst_ip`
  - `class`
  - `bytes`
  - `packets`
  - `connections_effective`
- `Filters`:
  - `process != ''`
- `Sort by`: `bytes desc`
- `Row limit`: `100`

Что показывает:

- какие процессы генерируют наибольший трафик

Рекомендуемые настройки:

- при желании добавь второй вариант этого виджета как `Bar Chart`
- `Dimension`: `process`
- `Metric`: `SUM(bytes)`

SQL-вариант для таблицы:

```sql
SELECT
    minute_dt,
    host,
    process,
    workload,
    src_ip,
    dst_ip,
    class,
    bytes,
    packets,
    connections_effective
FROM default.if_flow_final
WHERE process != ''
ORDER BY bytes DESC
LIMIT 100
```

SQL-вариант для bar chart по процессам:

```sql
SELECT
    process,
    workload,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections_effective) AS total_connections
FROM default.if_flow_final
WHERE process != ''
GROUP BY process, workload
ORDER BY total_bytes DESC
LIMIT 50
```

## 6. TCP Flows Без SYN

- `Chart type`: `Table`
- `Dataset`: `default.if_flow_final`
- `Columns`:
  - `minute_dt`
  - `host`
  - `src_ip`
  - `src_port`
  - `dst_ip`
  - `dst_port`
  - `class`
  - `tcp_seen_without_syn`
  - `connection_inferred`
  - `bytes`
  - `packets`
  - `process`
- `Filters`:
  - `proto = 6`
  - `tcp_seen_without_syn = true`
- `Sort by`: `minute_dt desc, bytes desc`
- `Row limit`: `200`

Что показывает:

- midstream TCP-flow и случаи, где начало соединения не было увидено

SQL-вариант:

```sql
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    class,
    tcp_seen_without_syn,
    connection_inferred,
    bytes,
    packets,
    process
FROM default.if_flow_final
WHERE proto = 6
  AND tcp_seen_without_syn = 1
ORDER BY minute_dt DESC, bytes DESC
LIMIT 200
```

## Фильтры Для Dashboard

Добавь `Native Filters`:

- `host`
- `direction`
- `class`
- `process`
- `workload`
- `src_ip`
- `dst_ip`

Рекомендуемая привязка фильтров:

- ко всем 6 виджетам

## Полезные Пресеты По Времени

Для dashboard удобно добавить быстрые time ranges:

- `Last 15 minutes`
- `Last 1 hour`
- `Last 24 hours`
- `Last 7 days`

## Базовая Логика Использования

- для отчетных графиков используй `default.if_flow_final`
- для поминутной динамики удобнее `default.if_flow_minute_host`
- для top talkers удобнее `default.if_flow_top_pairs`
