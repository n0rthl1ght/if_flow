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
WHERE $__timeFilter(minute_dt)
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
