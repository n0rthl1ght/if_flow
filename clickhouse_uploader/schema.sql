CREATE TABLE IF NOT EXISTS default.if_flow
(
    event_date Date DEFAULT toDate(minute_ts),
    minute_ts UInt64,
    minute_iso String,
    record_type LowCardinality(String),
    host LowCardinality(String),
    iface LowCardinality(String),
    proto UInt8,
    class LowCardinality(String),
    direction LowCardinality(String),
    pid Int32 DEFAULT -1,
    attr_source LowCardinality(String) DEFAULT 'unknown',
    process String DEFAULT '',
    cmdline String DEFAULT '',
    workload String DEFAULT '',
    sni String DEFAULT '',
    host_name String DEFAULT '',
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    packets UInt64,
    bytes UInt64,
    bytes_human String,
    connections UInt64,
    connections_effective UInt64 DEFAULT 0,
    connection_inferred Bool DEFAULT false,
    tcp_seen_without_syn Bool DEFAULT false,
    first_seen_iso String DEFAULT '',
    last_seen_iso String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY event_date
ORDER BY (event_date, minute_ts, host, src_ip, src_port, dst_ip, dst_port, proto, record_type)
TTL event_date + INTERVAL 7 DAY DELETE;
