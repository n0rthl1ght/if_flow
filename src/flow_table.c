#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "flow_table.h"

/* The flow table is keyed by the exact per-direction 5-tuple inside one minute bucket. */
static int flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
    return a->proto == b->proto &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           strcmp(a->src_ip, b->src_ip) == 0 &&
           strcmp(a->dst_ip, b->dst_ip) == 0;
}

static void safe_copy(char *dst, size_t sz, const char *src) {
    size_t i;
    if (!dst || sz == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < sz && src[i] != '\0'; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

static uint64_t minute_bucket_for(double now_sec) {
    uint64_t now_u64 = (uint64_t)now_sec;
    return now_u64 - (now_u64 % 60ULL);
}

const char *attr_source_str(attr_source_t attr_source) {
    switch (attr_source) {
        case ATTR_SRC_EBPF: return "ebpf";
        case ATTR_SRC_PROC: return "proc";
        default: return "unknown";
    }
}

const char *flow_direction_str(flow_direction_t direction) {
    switch (direction) {
        case FLOW_DIR_IN: return "in";
        case FLOW_DIR_OUT: return "out";
        case FLOW_DIR_INTERNAL: return "internal";
        case FLOW_DIR_TRANSIT: return "transit";
        default: return "unknown";
    }
}

void flow_table_init(flow_table_t *ft, size_t max_flows) {
    if (!ft) return;
    memset(ft, 0, sizeof(*ft));
    ft->max_flows = max_flows;
}

void flow_table_free(flow_table_t *ft) {
    if (!ft) return;
    free(ft->entries);
    ft->entries = NULL;
    ft->len = 0;
    ft->cap = 0;
}

void flow_table_touch(flow_table_t *ft, const flow_key_t *key, flow_direction_t direction,
                      int pid, const char *process, const char *cmdline, const char *workload,
                      const char *sni, const char *host, const char *class_tag, attr_source_t attr_source,
                      uint64_t bytes, int new_connection, double now_sec) {
    size_t i;
    uint64_t minute_bucket;

    if (!ft || !key) return;
    minute_bucket = minute_bucket_for(now_sec);

    /*
     * Update an existing minute bucket entry when the same directional 5-tuple
     * is seen again. This keeps aggregation fully in memory and avoids any
     * packet-level persistence after the counters are merged.
     */
    for (i = 0; i < ft->len; ++i) {
        flow_entry_t *e = &ft->entries[i];
        if (e->minute_bucket != minute_bucket) continue;
        if (!flow_key_equal(&e->key, key)) continue;
        if (e->direction != direction) continue;

        e->packets++;
        e->bytes += bytes;
        /* For the minute bucket prototype we count one connection per unique
         * 5-tuple to avoid SYN retransmits inflating the counter. */
        if (new_connection && key->proto != IPPROTO_UDP && e->connections == 0) e->connections = 1;
        /*
         * Identity fields are filled opportunistically. Once we learn a better
         * PID/process attribution for a flow we keep it for subsequent updates.
         */
        if (e->pid < 0 && pid >= 0) {
            e->pid = pid;
            safe_copy(e->process, sizeof(e->process), process);
            safe_copy(e->cmdline, sizeof(e->cmdline), cmdline);
            safe_copy(e->workload, sizeof(e->workload), workload);
            e->attr_source = attr_source;
        }
        if (e->sni[0] == '\0' && sni && sni[0]) safe_copy(e->sni, sizeof(e->sni), sni);
        if (e->host[0] == '\0' && host && host[0]) safe_copy(e->host, sizeof(e->host), host);
        if (e->class_tag[0] == '\0' && class_tag && class_tag[0]) safe_copy(e->class_tag, sizeof(e->class_tag), class_tag);
        e->last_seen = now_sec;
        e->dirty = 1;
        return;
    }

    /*
     * Growth is bounded by max_flows so a traffic spike cannot grow memory
     * without limit. If the cap is reached we drop new keys but keep updating
     * already known flows.
     */
    if (ft->len == ft->cap) {
        size_t new_cap = ft->cap ? ft->cap * 2 : 4096;
        flow_entry_t *new_entries;

        if (new_cap > ft->max_flows) new_cap = ft->max_flows;
        if (ft->cap == ft->max_flows) return;

        new_entries = (flow_entry_t *)realloc(ft->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) return;

        ft->entries = new_entries;
        ft->cap = new_cap;
    }

    /* First packet for this minute/key pair: create a fresh aggregate entry. */
    ft->entries[ft->len].key = *key;
    ft->entries[ft->len].direction = direction;
    ft->entries[ft->len].pid = pid;
    safe_copy(ft->entries[ft->len].process, sizeof(ft->entries[ft->len].process), process);
    safe_copy(ft->entries[ft->len].cmdline, sizeof(ft->entries[ft->len].cmdline), cmdline);
    safe_copy(ft->entries[ft->len].workload, sizeof(ft->entries[ft->len].workload), workload);
    safe_copy(ft->entries[ft->len].sni, sizeof(ft->entries[ft->len].sni), sni);
    safe_copy(ft->entries[ft->len].host, sizeof(ft->entries[ft->len].host), host);
    safe_copy(ft->entries[ft->len].class_tag, sizeof(ft->entries[ft->len].class_tag), class_tag);
    ft->entries[ft->len].attr_source = attr_source;
    ft->entries[ft->len].packets = 1;
    ft->entries[ft->len].bytes = bytes;
    ft->entries[ft->len].connections = new_connection ? 1 : (key->proto == IPPROTO_UDP ? 1 : 0);
    ft->entries[ft->len].minute_bucket = minute_bucket;
    ft->entries[ft->len].first_seen = now_sec;
    ft->entries[ft->len].last_seen = now_sec;
    ft->entries[ft->len].last_emit = 0.0;
    ft->entries[ft->len].dirty = 1;
    ft->len++;
}

void flow_table_emit_ready(flow_table_t *ft, double min_interval_sec, double now_sec,
                           flow_flush_cb cb, void *ctx) {
    size_t i;

    if (!ft || !cb) return;

    /*
     * Streaming emission is rate-limited per flow entry. Consumers get fresh
     * counters quickly, but not on every single packet arrival.
     */
    for (i = 0; i < ft->len; ++i) {
        flow_entry_t *e = &ft->entries[i];
        if (!e->dirty) continue;
        if (e->last_emit > 0.0 && (now_sec - e->last_emit) < min_interval_sec) continue;
        cb(e, 0, ctx);
        e->dirty = 0;
        e->last_emit = now_sec;
    }
}

void flow_table_flush_older_than(flow_table_t *ft, uint64_t minute_bucket,
                                 flow_flush_cb cb, void *ctx) {
    size_t read_idx;
    size_t write_idx;

    if (!ft) return;

    /*
     * Final flush compacts the array in place: old minute buckets are emitted
     * and dropped, newer buckets are kept by sliding them toward the front.
     */
    write_idx = 0;
    for (read_idx = 0; read_idx < ft->len; ++read_idx) {
        flow_entry_t *e = &ft->entries[read_idx];

        if (e->minute_bucket < minute_bucket) {
            if (cb) cb(e, 1, ctx);
            continue;
        }

        if (write_idx != read_idx) ft->entries[write_idx] = ft->entries[read_idx];
        write_idx++;
    }

    ft->len = write_idx;
}
