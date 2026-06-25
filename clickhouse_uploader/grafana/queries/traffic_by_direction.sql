SELECT
  toStartOfMinute(minute_dt) AS time,
  sumIf(bytes, direction = 'in') AS "in",
  sumIf(bytes, direction = 'out') AS "out",
  sumIf(bytes, direction = 'internal') AS "internal",
  sumIf(bytes, direction = 'transit') AS "transit"
FROM default.if_flow_minute_host
WHERE $__timeFilter(minute_dt)
GROUP BY time
ORDER BY time
