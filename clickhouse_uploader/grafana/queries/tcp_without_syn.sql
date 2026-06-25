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
WHERE $__timeFilter(minute_dt)
  AND proto = 6
  AND tcp_seen_without_syn = 1
ORDER BY minute_dt DESC, bytes DESC
LIMIT 200
