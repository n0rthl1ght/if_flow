-- if_flow investigation queries
-- Базовый набор под задачу:
-- "на каждом хосте откуда и куда какие объемы ходили,
-- источник ip, порт, тип протокола,
-- получатель ip, порт, тип протокола,
-- кол-во соединений, пакетов и объем трафика,
-- и интервал времени, желательно поминутно"

-- 1. Базовый поминутный отчет по всем flow на всех хостах
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 2. То же, но только по одному хосту
-- Замени 'RLEF-XX' на нужный host
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE host = 'RLEF-XX'
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 3. Поминутный отчет по конкретному временному окну
-- Замени границы окна на нужные
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE minute_dt >= toDateTime('2026-06-23 00:00:00')
  AND minute_dt <  toDateTime('2026-06-24 00:00:00')
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 4. Топ src -> dst пар по объему на каждом хосте
SELECT
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
GROUP BY
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port
ORDER BY bytes DESC
LIMIT 200;

-- 5. Топ src -> dst пар по объему на одном хосте
-- Замени 'RLEF-XX' на нужный host
SELECT
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE host = 'RLEF-XX'
GROUP BY
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port
ORDER BY bytes DESC
LIMIT 200;

-- 6. Суммарный трафик по хостам
SELECT
    host,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
GROUP BY host
ORDER BY bytes DESC;

-- 7. Суммарный трафик по протоколам/классам на каждом хосте
SELECT
    host,
    proto,
    class,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
GROUP BY host, proto, class
ORDER BY host, bytes DESC;

-- 8. Поминутная динамика по хостам
SELECT
    minute_dt,
    host,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
GROUP BY minute_dt, host
ORDER BY minute_dt DESC, bytes DESC;

-- 9. Поминутная динамика по направлениям на каждом хосте
SELECT
    minute_dt,
    host,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
GROUP BY minute_dt, host, direction
ORDER BY minute_dt DESC, host, bytes DESC;

-- 10. Детальный отчет по конкретному src_ip
-- Замени адрес на нужный
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE src_ip = '172.20.35.49'
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 11. Детальный отчет по конкретному dst_ip
-- Замени адрес на нужный
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE dst_ip = '172.20.35.49'
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 12. Детальный отчет по конкретной паре src -> dst
-- Замени адреса на нужные
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE src_ip = '172.20.35.49'
  AND dst_ip = '172.64.155.209'
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 13. Детальный отчет по порту назначения
-- Удобно для 443/53/3306/5432 и т.п.
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE dst_port = 443
GROUP BY
    minute_dt,
    host,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 14. Отчет по всем flow с process attribution
SELECT
    minute_dt,
    host,
    process,
    workload,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction,
    sum(connections_effective) AS connections,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.if_flow_final
WHERE process != ''
GROUP BY
    minute_dt,
    host,
    process,
    workload,
    src_ip,
    src_port,
    proto,
    class,
    dst_ip,
    dst_port,
    direction
ORDER BY minute_dt DESC, bytes DESC;

-- 15. Краткий отчет для приказа: одна строка = host + minute + tuple
SELECT
    minute_dt AS interval_minute,
    host,
    src_ip AS source_ip,
    src_port AS source_port,
    proto AS protocol_id,
    class AS protocol_class,
    dst_ip AS destination_ip,
    dst_port AS destination_port,
    sum(connections_effective) AS connection_count,
    sum(packets) AS packet_count,
    sum(bytes) AS traffic_bytes
FROM default.if_flow_final
GROUP BY
    interval_minute,
    host,
    source_ip,
    source_port,
    protocol_id,
    protocol_class,
    destination_ip,
    destination_port
ORDER BY interval_minute DESC, traffic_bytes DESC;
