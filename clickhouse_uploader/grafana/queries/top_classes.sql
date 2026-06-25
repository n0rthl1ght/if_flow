SELECT
  class,
  sum(bytes) AS total_bytes,
  sum(packets) AS total_packets,
  sum(connections_effective) AS total_connections
FROM default.if_flow_final
WHERE $__timeFilter(minute_dt)
GROUP BY class
ORDER BY total_bytes DESC
LIMIT 20
