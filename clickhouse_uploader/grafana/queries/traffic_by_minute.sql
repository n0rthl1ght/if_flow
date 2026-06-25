SELECT
  toStartOfMinute(minute_dt) AS time,
  host,
  sum(bytes) AS total_bytes
FROM default.if_flow_minute_host
WHERE $__timeFilter(minute_dt)
GROUP BY time, host
ORDER BY time
