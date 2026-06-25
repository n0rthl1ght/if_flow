#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

void config_set_defaults(app_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    /* Defaults are tuned for an always-on host agent, not a one-shot CLI tool. */
    snprintf(cfg->interface, sizeof(cfg->interface), "any");
    cfg->minute_flush_sec = 60;
    cfg->stream_flush_sec = 1;
    cfg->idle_timeout_sec = 120;
    cfg->max_flows = 200000;
    cfg->include_identity_fields = 1;
    cfg->use_ebpf = 1;
    cfg->use_datapath = 1;
    cfg->resolver_ttl_sec = 20.0;
    cfg->resolver_refresh_sec = 0.50;
    cfg->ebpf_ttl_sec = 20.0;
    cfg->datapath_ttl_sec = 5.0;
    snprintf(cfg->bpf_object, sizeof(cfg->bpf_object), "bpf/if_flow.bpf.o");
    snprintf(cfg->json_path, sizeof(cfg->json_path), "if_flow.jsonl");
    cfg->json_max_file_size_bytes = 0;
}

void config_print_help(const char *argv0) {
    printf("Usage: %s [options]\n", argv0);
    printf("\n");
    printf("  -i, --interface IFACE      Capture interface (default: any)\n");
    printf("      --flush-sec N          Minute flush interval in seconds (default: 60)\n");
    printf("      --stream-flush-sec N   Emit active flow updates every N sec (default: 1)\n");
    printf("      --idle-timeout-sec N   Idle timeout for flows (default: 120)\n");
    printf("      --max-flows N          Maximum in-memory flows (default: 200000)\n");
    printf("      --ebpf                 Enable eBPF connect attribution (default: on)\n");
    printf("      --no-ebpf              Disable eBPF and use /proc fallback only\n");
    printf("      --datapath             Enable eBPF datapath attribution (default: on)\n");
    printf("      --no-datapath          Disable datapath kprobes and use connect tracker only\n");
    printf("      --ebpf-ttl-sec N       eBPF cache TTL in seconds (default: 20)\n");
    printf("      --datapath-ttl-sec N   Datapath cache TTL in seconds (default: 5)\n");
    printf("      --bpf-object PATH      Path to compiled BPF object\n");
    printf("      --resolver-ttl-sec N   Identity cache TTL in seconds (default: 20)\n");
    printf("      --resolver-refresh-sec N  Minimum /proc refresh interval (default: 0.50)\n");
    printf("      --json-path PATH       JSONL output path (default: if_flow.jsonl)\n");
    printf("      --json-max-file-size-mb N  Rotate JSONL when file reaches N MiB (default: disabled)\n");
    printf("      --identity-fields      Include pid/process attribution fields (default: on)\n");
    printf("      --no-identity-fields   Omit pid/attr_source/process/cmdline from output\n");
    printf("      --no-stdout            Disable stdout flow output\n");
    printf("      --selftest             Run synthetic self-test without live capture\n");
}

int config_parse_args(app_config_t *cfg, int argc, char **argv) {
    int i;

    if (!cfg) return -1;

    /*
     * Keep parsing intentionally simple and dependency-free. The binary is meant
     * to stay lightweight, so argv is handled manually instead of using getopt.
     */
    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            config_print_help(argv[0]);
            return 1;
        }
        if ((!strcmp(arg, "-i") || !strcmp(arg, "--interface")) && i + 1 < argc) {
            snprintf(cfg->interface, sizeof(cfg->interface), "%s", argv[++i]);
            continue;
        }
        if (!strcmp(arg, "--flush-sec") && i + 1 < argc) {
            cfg->minute_flush_sec = atoi(argv[++i]);
            if (cfg->minute_flush_sec < 1) cfg->minute_flush_sec = 60;
            continue;
        }
        if (!strcmp(arg, "--stream-flush-sec") && i + 1 < argc) {
            cfg->stream_flush_sec = atoi(argv[++i]);
            if (cfg->stream_flush_sec < 1) cfg->stream_flush_sec = 1;
            continue;
        }
        if (!strcmp(arg, "--idle-timeout-sec") && i + 1 < argc) {
            cfg->idle_timeout_sec = atoi(argv[++i]);
            if (cfg->idle_timeout_sec < 1) cfg->idle_timeout_sec = 120;
            continue;
        }
        if (!strcmp(arg, "--max-flows") && i + 1 < argc) {
            cfg->max_flows = atoi(argv[++i]);
            if (cfg->max_flows < 1024) cfg->max_flows = 1024;
            continue;
        }
        if (!strcmp(arg, "--ebpf")) {
            cfg->use_ebpf = 1;
            continue;
        }
        if (!strcmp(arg, "--no-ebpf")) {
            cfg->use_ebpf = 0;
            continue;
        }
        if (!strcmp(arg, "--datapath")) {
            cfg->use_datapath = 1;
            continue;
        }
        if (!strcmp(arg, "--no-datapath")) {
            cfg->use_datapath = 0;
            continue;
        }
        if (!strcmp(arg, "--ebpf-ttl-sec") && i + 1 < argc) {
            cfg->ebpf_ttl_sec = atof(argv[++i]);
            if (cfg->ebpf_ttl_sec < 1.0) cfg->ebpf_ttl_sec = 1.0;
            continue;
        }
        if (!strcmp(arg, "--datapath-ttl-sec") && i + 1 < argc) {
            cfg->datapath_ttl_sec = atof(argv[++i]);
            if (cfg->datapath_ttl_sec < 1.0) cfg->datapath_ttl_sec = 1.0;
            continue;
        }
        if (!strcmp(arg, "--bpf-object") && i + 1 < argc) {
            snprintf(cfg->bpf_object, sizeof(cfg->bpf_object), "%s", argv[++i]);
            continue;
        }
        if (!strcmp(arg, "--resolver-ttl-sec") && i + 1 < argc) {
            cfg->resolver_ttl_sec = atof(argv[++i]);
            if (cfg->resolver_ttl_sec < 1.0) cfg->resolver_ttl_sec = 1.0;
            continue;
        }
        if (!strcmp(arg, "--resolver-refresh-sec") && i + 1 < argc) {
            cfg->resolver_refresh_sec = atof(argv[++i]);
            if (cfg->resolver_refresh_sec < 0.05) cfg->resolver_refresh_sec = 0.05;
            continue;
        }
        if (!strcmp(arg, "--json-path") && i + 1 < argc) {
            snprintf(cfg->json_path, sizeof(cfg->json_path), "%s", argv[++i]);
            continue;
        }
        if (!strcmp(arg, "--json-max-file-size-mb") && i + 1 < argc) {
            long mb = atol(argv[++i]);
            if (mb < 0) mb = 0;
            cfg->json_max_file_size_bytes = (size_t)mb * 1024U * 1024U;
            continue;
        }
        if (!strcmp(arg, "--identity-fields")) {
            cfg->include_identity_fields = 1;
            continue;
        }
        if (!strcmp(arg, "--no-identity-fields")) {
            cfg->include_identity_fields = 0;
            continue;
        }
        if (!strcmp(arg, "--no-stdout")) {
            cfg->no_stdout = 1;
            continue;
        }
        if (!strcmp(arg, "--selftest")) {
            cfg->selftest = 1;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", arg);
        return -1;
    }

    return 0;
}
