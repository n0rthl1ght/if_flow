#ifndef IF_FLOW_EBPF_TRACKER_H
#define IF_FLOW_EBPF_TRACKER_H

#include <stddef.h>

#include <bpf/libbpf.h>

#include "flow_table.h"

typedef struct {
    /* 5-tuple key as seen by the packet path or connect() hook. */
    flow_key_t key;
    /* Best process identity currently associated with this flow key. */
    int pid;
    char process[IF_FLOW_MAX_PROC_NAME];
    /*
     * Original event source inside the eBPF program:
     * connect()-style metadata usually lives longer than datapath hints,
     * so user space applies different TTL values to each source.
     */
    uint8_t source;
    /* Monotonic-ish wall-clock timestamp used for cache expiration. */
    double ts;
} ebpf_cache_entry_t;

typedef struct {
    struct bpf_object *obj;
    struct ring_buffer *rb;
    /* In-memory cache that bridges short-lived eBPF events to later packets. */
    ebpf_cache_entry_t *entries;
    size_t len;
    size_t cap;
    /* Separate TTLs let us trust connect() and datapath hints differently. */
    double connect_ttl_sec;
    double datapath_ttl_sec;
    int enable_datapath;
    char object_path[1024];
} ebpf_tracker_t;

void ebpf_tracker_init(ebpf_tracker_t *tracker, double connect_ttl_sec, double datapath_ttl_sec,
                       int enable_datapath, const char *object_path);
void ebpf_tracker_close(ebpf_tracker_t *tracker);
int ebpf_tracker_open(ebpf_tracker_t *tracker);
int ebpf_tracker_poll(ebpf_tracker_t *tracker, int timeout_ms);
int ebpf_tracker_lookup(ebpf_tracker_t *tracker, const flow_key_t *key,
                        int *pid, char *process, size_t process_sz);

#endif
