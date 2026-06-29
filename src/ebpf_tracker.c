#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ebpf_tracker.h"
#include "shared.h"

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
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

static int flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
    return a->proto == b->proto &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           strcmp(a->src_ip, b->src_ip) == 0 &&
           strcmp(a->dst_ip, b->dst_ip) == 0;
}

static int flow_key_equal_rev(const flow_key_t *a, const flow_key_t *b) {
    return a->proto == b->proto &&
           a->src_port == b->dst_port &&
           a->dst_port == b->src_port &&
           strcmp(a->src_ip, b->dst_ip) == 0 &&
           strcmp(a->dst_ip, b->src_ip) == 0;
}

/*
 * Kernel worker threads often appear around packet processing, but they are not
 * the user workload that opened the socket. Filtering them out avoids replacing
 * a good attribution with an infrastructure thread name.
 */
static int is_kernel_thread_comm(const char *comm) {
    const char *c = comm ? comm : "";
    return strstr(c, "ksoftirqd") != NULL ||
           strstr(c, "kworker") != NULL ||
           strstr(c, "rcu_") != NULL ||
           strstr(c, "migration/") != NULL ||
           strstr(c, "idle_inject/") != NULL;
}

static int ebpf_identity_usable(int pid, const char *comm) {
    if (pid <= 0) return 0;
    if (!comm || !comm[0]) return 0;
    if (!strcmp(comm, "unknown")) return 0;
    if (is_kernel_thread_comm(comm)) return 0;
    return 1;
}

static double entry_ttl_sec(const ebpf_tracker_t *tracker, const ebpf_cache_entry_t *entry) {
    if (!tracker || !entry) return 0.0;
    return entry->source == EVENT_SRC_DATAPATH ? tracker->datapath_ttl_sec : tracker->connect_ttl_sec;
}

/*
 * eBPF events are only hints that help us attribute later packets to a process.
 * We keep them in a compact user-space cache and periodically drop stale entries
 * so reverse lookups do not grow forever on busy hosts.
 */
static void ebpf_cache_prune(ebpf_tracker_t *tracker) {
    size_t r;
    size_t w = 0;
    if (!tracker) return;
    for (r = 0; r < tracker->len; ++r) {
        double ttl = entry_ttl_sec(tracker, &tracker->entries[r]);
        if (tracker->entries[r].ts >= now_sec() - ttl) {
            if (w != r) tracker->entries[w] = tracker->entries[r];
            ++w;
        }
    }
    tracker->len = w;
}

static void ebpf_cache_put(ebpf_tracker_t *tracker, const flow_key_t *key,
                           int pid, const char *process, uint8_t source) {
    size_t i;
    if (!tracker || !key || !ebpf_identity_usable(pid, process)) return;
    /*
     * Update in place when the same flow key is seen again. This keeps the most
     * recent process identity and refreshes the TTL without creating duplicates.
     */
    for (i = 0; i < tracker->len; ++i) {
        if (tracker->entries[i].source == source && flow_key_equal(&tracker->entries[i].key, key)) {
            tracker->entries[i].pid = pid;
            safe_copy(tracker->entries[i].process, sizeof(tracker->entries[i].process), process);
            tracker->entries[i].source = source;
            tracker->entries[i].ts = now_sec();
            return;
        }
    }
    /* Grow lazily because the number of concurrent attribution hints is workload-dependent. */
    if (tracker->len == tracker->cap) {
        size_t new_cap = tracker->cap ? tracker->cap * 2 : 4096;
        ebpf_cache_entry_t *new_entries =
            (ebpf_cache_entry_t *)realloc(tracker->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) return;
        tracker->entries = new_entries;
        tracker->cap = new_cap;
    }
    tracker->entries[tracker->len].key = *key;
    tracker->entries[tracker->len].pid = pid;
    safe_copy(tracker->entries[tracker->len].process, sizeof(tracker->entries[tracker->len].process), process);
    tracker->entries[tracker->len].source = source;
    tracker->entries[tracker->len].ts = now_sec();
    tracker->len++;
    ebpf_cache_prune(tracker);
}

static int libbpf_log_fn(enum libbpf_print_level level, const char *fmt, va_list ap) {
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, ap);
}

static int on_ebpf_event(void *ctx, void *data, size_t data_sz) {
    ebpf_tracker_t *tracker = (ebpf_tracker_t *)ctx;
    const struct ebpf_event_v4 *e = (const struct ebpf_event_v4 *)data;
    flow_key_t key;
    struct in_addr addr;

    /*
     * The BPF side emits a compact IPv4 event. User space converts it into the
     * same canonical flow key format used by the packet aggregator so later
     * packet hits can be matched against this identity record.
     */
    if (!tracker || !data || data_sz < sizeof(struct ebpf_event_v4)) return 0;

    memset(&key, 0, sizeof(key));
    key.proto = e->t.proto;
    addr.s_addr = e->t.saddr;
    inet_ntop(AF_INET, &addr, key.src_ip, sizeof(key.src_ip));
    addr.s_addr = e->t.daddr;
    inet_ntop(AF_INET, &addr, key.dst_ip, sizeof(key.dst_ip));
    key.src_port = e->t.sport;
    key.dst_port = e->t.dport;

    ebpf_cache_put(tracker, &key, (int)e->pid, e->comm, e->source);
    return 0;
}

void ebpf_tracker_init(ebpf_tracker_t *tracker, double connect_ttl_sec, double datapath_ttl_sec,
                       int enable_datapath, const char *object_path) {
    if (!tracker) return;
    memset(tracker, 0, sizeof(*tracker));
    tracker->connect_ttl_sec = connect_ttl_sec;
    tracker->datapath_ttl_sec = datapath_ttl_sec;
    tracker->enable_datapath = enable_datapath;
    safe_copy(tracker->object_path, sizeof(tracker->object_path), object_path ? object_path : "bpf/if_flow.bpf.o");
}

int ebpf_tracker_open(ebpf_tracker_t *tracker) {
    struct bpf_object_open_opts open_opts;
    struct bpf_program *prog;
    struct bpf_map *events_map;
    int map_fd;
    int err;

    if (!tracker) return -1;

    memset(&open_opts, 0, sizeof(open_opts));
    open_opts.sz = sizeof(open_opts);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_log_fn);

    tracker->obj = bpf_object__open_file(tracker->object_path, &open_opts);
    if (!tracker->obj) return -1;

    err = bpf_object__load(tracker->obj);
    if (err) return -1;

    /*
     * The object may contain both connect()-oriented hooks and datapath hooks.
     * Datapath attachment is optional because it is more expensive, while the
     * connect path alone is usually enough for outbound attribution.
     */
    bpf_object__for_each_program(prog, tracker->obj) {
        const char *name = bpf_program__name(prog);
        if (!tracker->enable_datapath && name &&
            (!strcmp(name, "kp_ip_local_out") || !strcmp(name, "kp_ip_rcv"))) {
            continue;
        }
        struct bpf_link *lnk = bpf_program__attach(prog);
        if (!lnk) return -1;
    }

    events_map = bpf_object__find_map_by_name(tracker->obj, "events");
    if (!events_map) return -1;
    map_fd = bpf_map__fd(events_map);
    tracker->rb = ring_buffer__new(map_fd, on_ebpf_event, tracker, NULL);
    if (!tracker->rb) return -1;
    return 0;
}

void ebpf_tracker_close(ebpf_tracker_t *tracker) {
    if (!tracker) return;
    if (tracker->rb) {
        ring_buffer__free(tracker->rb);
        tracker->rb = NULL;
    }
    if (tracker->obj) {
        bpf_object__close(tracker->obj);
        tracker->obj = NULL;
    }
    free(tracker->entries);
    tracker->entries = NULL;
    tracker->len = 0;
    tracker->cap = 0;
}

int ebpf_tracker_poll(ebpf_tracker_t *tracker, int timeout_ms) {
    int rc;
    if (!tracker || !tracker->rb) return 0;
    /*
     * Polling both consumes fresh events and gives us a convenient place to age
     * out stale cache entries even during low traffic periods.
     */
    rc = ring_buffer__poll(tracker->rb, timeout_ms);
    ebpf_cache_prune(tracker);
    if (rc < 0 && rc != -EINTR) return rc;
    return rc;
}

int ebpf_tracker_lookup(ebpf_tracker_t *tracker, const flow_key_t *key,
                        int *pid, char *process, size_t process_sz) {
    ssize_t i;
    if (!tracker || !key || !pid || !process) return 0;
    /*
     * Reverse iteration favors the newest attribution first. We also accept a
     * reversed 5-tuple because inbound packets often arrive after the outbound
     * connect() event that created the original cache entry.
     */
    for (i = (ssize_t)tracker->len - 1; i >= 0; --i) {
        double ttl = entry_ttl_sec(tracker, &tracker->entries[i]);
        if (tracker->entries[i].ts < now_sec() - ttl) continue;
        if (flow_key_equal(&tracker->entries[i].key, key) ||
            flow_key_equal_rev(&tracker->entries[i].key, key)) {
            *pid = tracker->entries[i].pid;
            safe_copy(process, process_sz, tracker->entries[i].process);
            return 1;
        }
    }
    return 0;
}
