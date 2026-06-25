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
WHERE $__timeFilter(minute_dt)
  AND process != ''
ORDER BY bytes DESC
LIMIT 100
