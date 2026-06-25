-- 1. Общий трафик по минутам
SELECT
    minute_dt,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections) AS total_connections
FROM default.if_flow_minute_host
GROUP BY minute_dt
ORDER BY minute_dt;

-- 2. Трафик по хостам
SELECT
    host,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections_effective) AS total_connections
FROM default.if_flow_final
GROUP BY host
ORDER BY total_bytes DESC;

-- 3. Топ направлений src -> dst
SELECT
    host,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    class,
    proto,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections_effective) AS total_connections
FROM default.if_flow_final
GROUP BY host, src_ip, src_port, dst_ip, dst_port, class, proto
ORDER BY total_bytes DESC
LIMIT 100;

-- 4. Топ class по объему
SELECT
    class,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections_effective) AS total_connections
FROM default.if_flow_final
GROUP BY class
ORDER BY total_bytes DESC;

-- 5. In/Out/Internal/Transit по объему
SELECT
    direction,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    sum(connections_effective) AS total_connections
FROM default.if_flow_final
GROUP BY direction
ORDER BY total_bytes DESC;

-- 6. Подозрительные TCP final-flow без SYN
SELECT
    minute_dt,
    host,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    class,
    process,
    workload,
    packets,
    bytes,
    connections_effective
FROM default.if_flow_final
WHERE proto = 6
  AND tcp_seen_without_syn = 1
ORDER BY minute_dt DESC, bytes DESC
LIMIT 200;

-- 7. Трафик по процессам
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
LIMIT 100;
