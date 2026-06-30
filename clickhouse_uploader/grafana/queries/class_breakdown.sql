SELECT
  minute_dt,
  class,
  host,
  src_ip,
  src_port,
  dst_ip,
  dst_port,
  direction,
  sum(bytes) AS total_bytes
FROM default.if_flow_final
WHERE $__timeFilter(toDateTime(minute_ts))
GROUP BY
  minute_dt,
  class,
  host,
  src_ip,
  src_port,
  dst_ip,
  dst_port,
  direction
ORDER BY
  minute_dt DESC,
  class ASC,
  total_bytes DESC
