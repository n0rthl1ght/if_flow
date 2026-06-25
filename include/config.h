#ifndef IF_FLOW_CONFIG_H
#define IF_FLOW_CONFIG_H

#include <stddef.h>

typedef struct {
    char interface[64];
    /* Final export cadence for completed minute buckets. */
    int minute_flush_sec;
    /* Streaming export cadence for still-active flows. */
    int stream_flush_sec;
    /* Flow eviction threshold when no packets were seen recently. */
    int idle_timeout_sec;
    int max_flows;
    int selftest;
    int no_stdout;
    int include_identity_fields;
    int use_ebpf;
    int use_datapath;
    /* Cache tuning for process attribution layers. */
    double resolver_ttl_sec;
    double resolver_refresh_sec;
    double ebpf_ttl_sec;
    double datapath_ttl_sec;
    char bpf_object[1024];
    char json_path[1024];
    /* Zero disables size-based rotation; non-zero rotates in MiB-sized chunks. */
    size_t json_max_file_size_bytes;
} app_config_t;

void config_set_defaults(app_config_t *cfg);
int config_parse_args(app_config_t *cfg, int argc, char **argv);
void config_print_help(const char *argv0);

#endif
