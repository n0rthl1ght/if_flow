#ifndef IF_FLOW_RESOLVER_H
#define IF_FLOW_RESOLVER_H

#include <stddef.h>
#include <stdint.h>

#include "flow_table.h"

typedef struct {
    /* Cached 5-tuple to PID resolution derived from /proc snapshots. */
    flow_key_t key;
    int pid;
    char process[IF_FLOW_MAX_PROC_NAME];
    char cmdline[IF_FLOW_MAX_CMDLINE];
    char workload[IF_FLOW_MAX_WORKLOAD];
    double ts;
} resolver_cache_entry_t;

typedef struct {
    resolver_cache_entry_t *entries;
    size_t len;
    size_t cap;
    /* How long a cached /proc resolution is trusted after discovery. */
    double ttl_sec;
    /* Minimum spacing between expensive /proc rescans on cache misses. */
    double refresh_sec;
    double last_refresh;
} resolver_t;

void resolver_init(resolver_t *resolver, double ttl_sec, double refresh_sec);
void resolver_free(resolver_t *resolver);
int resolver_lookup(resolver_t *resolver, const flow_key_t *key,
                    int *pid, char *process, size_t process_sz,
                    char *cmdline, size_t cmdline_sz,
                    char *workload, size_t workload_sz);
void resolver_read_identity_by_pid(int pid, char *process, size_t process_sz,
                                   char *cmdline, size_t cmdline_sz,
                                   char *workload, size_t workload_sz);

#endif
