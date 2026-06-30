SELECT
  minute_dt,
  host,
  if(
    '${name_mode}' = 'mapped' AND ifNull(src_alias.alias, '') != '',
    src_alias.alias,
    t.src_ip
  ) AS src_ip,
  src_port,
  if(
    '${name_mode}' = 'mapped' AND ifNull(dst_alias.alias, '') != '',
    dst_alias.alias,
    t.dst_ip
  ) AS dst_ip,
  dst_port,
  class,
  bytes,
  packets
FROM default.if_flow_top_pairs AS t
LEFT JOIN default.ip_aliases AS src_alias
  ON t.src_ip = src_alias.ip
LEFT JOIN default.ip_aliases AS dst_alias
  ON t.dst_ip = dst_alias.ip
WHERE $__timeFilter(toDateTime(minute_ts))
  AND (
    '${traffic_filter:raw}' = 'All'
    OR host IN (${traffic_filter:sqlstring})
  )
ORDER BY bytes DESC
LIMIT 50
