#ifndef IF_FLOW_FLOW_TABLE_H
#define IF_FLOW_FLOW_TABLE_H

#include <stddef.h>
#include <stdint.h>

#define IF_FLOW_MAX_IP_STR 64
#define IF_FLOW_MAX_PROC_NAME 64
#define IF_FLOW_MAX_CMDLINE 512
#define IF_FLOW_MAX_WORKLOAD 192
#define IF_FLOW_MAX_NAME 256
#define IF_FLOW_MAX_CLASS 32

typedef enum {
    FLOW_DIR_UNKNOWN = 0,
    FLOW_DIR_IN = 1,
    FLOW_DIR_OUT = 2,
    FLOW_DIR_INTERNAL = 3,
    FLOW_DIR_TRANSIT = 4
} flow_direction_t;

typedef enum {
    ATTR_SRC_UNKNOWN = 0,
    ATTR_SRC_EBPF = 1,
    ATTR_SRC_PROC = 2
} attr_source_t;

typedef struct {
    /* Canonical 5-tuple used as the aggregation key inside a minute bucket. */
    uint8_t proto;
    char src_ip[IF_FLOW_MAX_IP_STR];
    uint16_t src_port;
    char dst_ip[IF_FLOW_MAX_IP_STR];
    uint16_t dst_port;
} flow_key_t;

typedef struct {
    flow_key_t key;
    flow_direction_t direction;
    /* Optional process identity attached from eBPF or /proc lookups. */
    int pid;
    char process[IF_FLOW_MAX_PROC_NAME];
    char cmdline[IF_FLOW_MAX_CMDLINE];
    char workload[IF_FLOW_MAX_WORKLOAD];
    /* Optional application-level names extracted from payload and headers. */
    char sni[IF_FLOW_MAX_NAME];
    char host[IF_FLOW_MAX_NAME];
    char class_tag[IF_FLOW_MAX_CLASS];
    attr_source_t attr_source;
    /* Counters accumulated for a single minute bucket. */
    uint64_t packets;
    uint64_t bytes;
    uint64_t connections;
    uint64_t minute_bucket;
    /* Timestamps support both final flushes and streaming update output. */
    double first_seen;
    double last_seen;
    double last_emit;
    /* Dirty means counters changed since the previous streaming emission. */
    int dirty;
} flow_entry_t;

typedef struct {
    /* Flat dynamic array keeps the hot path simple and cache-friendly. */
    flow_entry_t *entries;
    size_t len;
    size_t cap;
    size_t max_flows;
} flow_table_t;

typedef void (*flow_flush_cb)(const flow_entry_t *entry, int is_final, void *ctx);

void flow_table_init(flow_table_t *ft, size_t max_flows);
void flow_table_free(flow_table_t *ft);
void flow_table_touch(flow_table_t *ft, const flow_key_t *key, flow_direction_t direction,
                      int pid, const char *process, const char *cmdline, const char *workload,
                      const char *sni, const char *host, const char *class_tag, attr_source_t attr_source,
                      uint64_t bytes, int new_connection, double now_sec);
void flow_table_emit_ready(flow_table_t *ft, double min_interval_sec, double now_sec,
                           flow_flush_cb cb, void *ctx);
void flow_table_flush_older_than(flow_table_t *ft, uint64_t minute_bucket,
                                 flow_flush_cb cb, void *ctx);
const char *flow_direction_str(flow_direction_t direction);
const char *attr_source_str(attr_source_t attr_source);

#endif
