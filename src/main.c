#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define PCAP_DONT_INCLUDE_PCAP_BPF_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if __has_include(<pcap.h>)
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "config.h"
#include "ebpf_tracker.h"
#include "flow_table.h"
#include "local_ip.h"
#include "parser.h"
#include "resolver.h"
#include "writer_jsonl.h"

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_RAW
#define DLT_RAW 12
#endif

typedef struct {
    app_config_t cfg;
    flow_table_t flows;
    int linktype;
    char hostname[256];
    local_ip_list_t local_ips;
    ebpf_tracker_t ebpf;
    resolver_t resolver;
    jsonl_writer_t writer;
} app_t;

static app_t g_app;
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint64_t minute_bucket_for(double t) {
    uint64_t v = (uint64_t)t;
    return v - (v % 60ULL);
}

static void format_minute_iso(uint64_t minute_bucket, char *out, size_t out_sz) {
    time_t tt = (time_t)minute_bucket;
    struct tm tmv;
    localtime_r(&tt, &tmv);
    strftime(out, out_sz, "%Y-%m-%dT%H:%M:00%z", &tmv);
}

static void format_bytes_human(uint64_t bytes, char *out, size_t out_sz) {
    static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)bytes;
    size_t idx = 0;
    while (v >= 1024.0 && idx + 1 < sizeof(units) / sizeof(units[0])) {
        v /= 1024.0;
        ++idx;
    }
    if (idx == 0) snprintf(out, out_sz, "%llu %s", (unsigned long long)bytes, units[idx]);
    else snprintf(out, out_sz, "%.2f %s", v, units[idx]);
}

static int flow_has_port(const flow_key_t *key, uint16_t port) {
    if (!key) return 0;
    return key->src_port == port || key->dst_port == port;
}

static int flow_has_any_port(const flow_key_t *key, const uint16_t *ports, size_t count) {
    size_t i;
    if (!key || !ports) return 0;
    for (i = 0; i < count; ++i) {
        if (flow_has_port(key, ports[i])) return 1;
    }
    return 0;
}

static int is_multicast_ip(const char *ip) {
    if (!ip || !ip[0]) return 0;
    return strncmp(ip, "224.", 4) == 0 ||
           strncmp(ip, "225.", 4) == 0 ||
           strncmp(ip, "226.", 4) == 0 ||
           strncmp(ip, "227.", 4) == 0 ||
           strncmp(ip, "228.", 4) == 0 ||
           strncmp(ip, "229.", 4) == 0 ||
           strncmp(ip, "230.", 4) == 0 ||
           strncmp(ip, "231.", 4) == 0 ||
           strncmp(ip, "232.", 4) == 0 ||
           strncmp(ip, "233.", 4) == 0 ||
           strncmp(ip, "234.", 4) == 0 ||
           strncmp(ip, "235.", 4) == 0 ||
           strncmp(ip, "236.", 4) == 0 ||
           strncmp(ip, "237.", 4) == 0 ||
           strncmp(ip, "238.", 4) == 0 ||
           strncmp(ip, "239.", 4) == 0 ||
           strncmp(ip, "ff", 2) == 0;
}

/*
 * Classification is intentionally heuristic and port-first. The goal is not
 * perfect protocol identification, but a stable operational label that makes
 * dashboards and investigations useful without deep packet retention.
 */
static const char *classify_flow(const flow_key_t *key, const char *sni, const char *host) {
    static const uint16_t http_ports[] = {80, 8000, 8008, 8080, 8888};
    static const uint16_t https_ports[] = {443, 8443, 9443};
    static const uint16_t quic_ports[] = {443, 8443, 9443};
    if (!key) return "other";
    if (flow_has_port(key, 5353)) return "mdns";
    if (flow_has_port(key, 5355)) return "llmnr";
    if (flow_has_port(key, 1900)) return "ssdp";
    if (flow_has_port(key, 53)) return "dns";
    if (flow_has_port(key, 853)) return "dot";
    if (flow_has_port(key, 123)) return "ntp";
    if (key->proto == IPPROTO_UDP &&
        flow_has_any_port(key, quic_ports, sizeof(quic_ports) / sizeof(quic_ports[0]))) return "quic";
    if (flow_has_any_port(key, http_ports, sizeof(http_ports) / sizeof(http_ports[0])) && host && host[0]) return "http";
    if (flow_has_any_port(key, https_ports, sizeof(https_ports) / sizeof(https_ports[0])) && sni && sni[0]) return "https";
    if (is_multicast_ip(key->dst_ip)) return "multicast";
    if ((sni && sni[0]) || (host && host[0])) return "named_app";
    if (flow_has_any_port(key, https_ports, sizeof(https_ports) / sizeof(https_ports[0]))) return "https";
    if (flow_has_any_port(key, http_ports, sizeof(http_ports) / sizeof(http_ports[0]))) return "http";
    if (flow_has_port(key, 111)) return "rpcbind";
    if (flow_has_port(key, 135) || flow_has_port(key, 593)) return "msrpc";
    if (flow_has_port(key, 22)) return "ssh";
    if (flow_has_port(key, 21)) return "ftp";
    if (flow_has_port(key, 20)) return "ftp_data";
    if (flow_has_port(key, 23)) return "telnet";
    if (flow_has_port(key, 873)) return "rsync";
    if (flow_has_port(key, 9418)) return "git";
    if (flow_has_port(key, 3690)) return "svn";
    if (flow_has_port(key, 25) || flow_has_port(key, 465) || flow_has_port(key, 587)) return "smtp";
    if (flow_has_port(key, 110) || flow_has_port(key, 995)) return "pop3";
    if (flow_has_port(key, 143) || flow_has_port(key, 993)) return "imap";
    if (flow_has_port(key, 389) || flow_has_port(key, 636)) return "ldap";
    if (flow_has_port(key, 88)) return "kerberos";
    if (flow_has_port(key, 1812) || flow_has_port(key, 1813)) return "radius";
    if (flow_has_port(key, 67) || flow_has_port(key, 68)) return "dhcp";
    if (flow_has_port(key, 69)) return "tftp";
    if (flow_has_port(key, 137) || flow_has_port(key, 138) || flow_has_port(key, 139)) return "netbios";
    if (flow_has_port(key, 445)) return "smb";
    if (flow_has_port(key, 2049)) return "nfs";
    if (flow_has_port(key, 3260)) return "iscsi";
    if (flow_has_port(key, 3306)) return "mysql";
    if (flow_has_port(key, 5432)) return "postgres";
    if (flow_has_port(key, 1433) || flow_has_port(key, 1434)) return "mssql";
    if (flow_has_port(key, 1521)) return "oracle";
    if (flow_has_port(key, 9042)) return "cassandra";
    if (flow_has_port(key, 26257)) return "cockroachdb";
    if (flow_has_port(key, 8123) || flow_has_port(key, 9000) || flow_has_port(key, 9004) ||
        flow_has_port(key, 9005) || flow_has_port(key, 9440)) return "clickhouse";
    if (flow_has_port(key, 6379)) return "redis";
    if (flow_has_port(key, 27017) || flow_has_port(key, 27018) || flow_has_port(key, 27019)) return "mongodb";
    if (flow_has_port(key, 11211)) return "memcached";
    if (flow_has_port(key, 5672) || flow_has_port(key, 5671)) return "amqp";
    if (flow_has_port(key, 15672) || flow_has_port(key, 15671)) return "rabbitmq_mgmt";
    if (flow_has_port(key, 1883) || flow_has_port(key, 8883)) return "mqtt";
    if (flow_has_port(key, 9092)) return "kafka";
    if (flow_has_port(key, 2181)) return "zookeeper";
    if (flow_has_port(key, 2379) || flow_has_port(key, 2380)) return "etcd";
    if (flow_has_port(key, 2375) || flow_has_port(key, 2376)) return "docker_api";
    if (flow_has_port(key, 6443)) return "k8s_api";
    if (flow_has_port(key, 10250)) return "kubelet";
    if (flow_has_port(key, 8500) || flow_has_port(key, 8502) || flow_has_port(key, 8600)) return "consul";
    if (flow_has_port(key, 8200) || flow_has_port(key, 8201)) return "vault";
    if (flow_has_port(key, 4646) || flow_has_port(key, 4647) || flow_has_port(key, 4648)) return "nomad";
    if (flow_has_port(key, 9200) || flow_has_port(key, 9300)) return "elasticsearch";
    if (flow_has_port(key, 5601)) return "kibana";
    if (flow_has_port(key, 9090)) return "prometheus";
    if (flow_has_port(key, 9093)) return "alertmanager";
    if (flow_has_port(key, 9100)) return "node_exporter";
    if (flow_has_port(key, 3000)) return "grafana";
    if (flow_has_port(key, 3100)) return "loki";
    if (flow_has_port(key, 5044)) return "logstash";
    if (flow_has_port(key, 24224)) return "fluentd";
    if (flow_has_port(key, 4317) || flow_has_port(key, 4318)) return "otlp";
    if (flow_has_port(key, 6831) || flow_has_port(key, 6832) || flow_has_port(key, 14250) ||
        flow_has_port(key, 14268) || flow_has_port(key, 16686)) return "tracing";
    if (flow_has_port(key, 8086)) return "influxdb";
    if (flow_has_port(key, 8125)) return "statsd";
    if (flow_has_port(key, 161) || flow_has_port(key, 162)) return "snmp";
    if (flow_has_port(key, 514) || flow_has_port(key, 6514)) return "syslog";
    if (flow_has_port(key, 631)) return "ipp";
    if (flow_has_port(key, 554)) return "rtsp";
    if (flow_has_port(key, 3389)) return "rdp";
    if (flow_has_port(key, 5900)) return "vnc";
    if (flow_has_port(key, 5060) || flow_has_port(key, 5061)) return "sip";
    if (flow_has_port(key, 500) || flow_has_port(key, 4500)) return "ipsec";
    if (flow_has_port(key, 1194)) return "openvpn";
    if (flow_has_port(key, 1701)) return "l2tp";
    if (flow_has_port(key, 1723)) return "pptp";
    if (flow_has_port(key, 51820) || flow_has_port(key, 51821)) return "wireguard";
    if (flow_has_port(key, 4789)) return "vxlan";
    if (flow_has_port(key, 6081)) return "geneve";
    if (flow_has_port(key, 179)) return "bgp";
    return "other";
}

static int flow_connection_inferred(const flow_entry_t *entry) {
    if (!entry) return 0;
    return entry->key.proto == IPPROTO_TCP && entry->packets > 0 && entry->connections == 0;
}

static int flow_tcp_seen_without_syn(const flow_entry_t *entry, int is_final) {
    if (!entry || !is_final) return 0;
    if (entry->key.proto != IPPROTO_TCP) return 0;
    if (entry->packets == 0) return 0;
    if (entry->connections != 0) return 0;
    return entry->attr_source == ATTR_SRC_EBPF || entry->attr_source == ATTR_SRC_PROC;
}

static uint64_t flow_connections_effective(const flow_entry_t *entry, int is_final) {
    if (!entry) return 0;
    if (flow_tcp_seen_without_syn(entry, is_final)) return 1;
    return entry->connections;
}

/* Direction is decided relative to IPs assigned to the current host. */
static flow_direction_t detect_direction(const char *src_ip, const char *dst_ip) {
    int src_local = local_ip_list_contains(&g_app.local_ips, src_ip);
    int dst_local = local_ip_list_contains(&g_app.local_ips, dst_ip);

    if (src_local && dst_local) return FLOW_DIR_INTERNAL;
    if (src_local) return FLOW_DIR_OUT;
    if (dst_local) return FLOW_DIR_IN;
    return FLOW_DIR_TRANSIT;
}

static void flush_flow_entry(const flow_entry_t *entry, int is_final, void *ctx) {
    app_t *app = (app_t *)ctx;
    char minute_iso[40];
    char bytes_human[32];
    if (!app || !entry) return;
    format_minute_iso(entry->minute_bucket, minute_iso, sizeof(minute_iso));
    format_bytes_human(entry->bytes, bytes_human, sizeof(bytes_human));

    if (!app->cfg.no_stdout) {
        if (app->cfg.include_identity_fields) {
            printf(
                "FLOW state=%s minute=%s host=%s iface=%s class=%s dir=%s proto=%u src=%s:%u dst=%s:%u pid=%d attr=%s process=%s workload=%s packets=%llu bytes=%s connections=%llu effective=%llu inferred=%s seen_without_syn=%s\n",
                is_final ? "final" : "update",
                minute_iso,
                app->hostname[0] ? app->hostname : "unknown",
                app->cfg.interface,
                entry->class_tag[0] ? entry->class_tag : "other",
                flow_direction_str(entry->direction),
                (unsigned)entry->key.proto,
                entry->key.src_ip,
                (unsigned)entry->key.src_port,
                entry->key.dst_ip,
                (unsigned)entry->key.dst_port,
                entry->pid,
                attr_source_str(entry->attr_source),
                entry->process[0] ? entry->process : "unknown",
                entry->workload[0] ? entry->workload : "-",
                (unsigned long long)entry->packets,
                bytes_human,
                (unsigned long long)entry->connections,
                (unsigned long long)flow_connections_effective(entry, is_final),
                flow_connection_inferred(entry) ? "yes" : "no",
                flow_tcp_seen_without_syn(entry, is_final) ? "yes" : "no"
            );
        } else {
            printf(
                "FLOW state=%s minute=%s host=%s iface=%s class=%s dir=%s proto=%u src=%s:%u dst=%s:%u workload=%s packets=%llu bytes=%s connections=%llu effective=%llu inferred=%s seen_without_syn=%s\n",
                is_final ? "final" : "update",
                minute_iso,
                app->hostname[0] ? app->hostname : "unknown",
                app->cfg.interface,
                entry->class_tag[0] ? entry->class_tag : "other",
                flow_direction_str(entry->direction),
                (unsigned)entry->key.proto,
                entry->key.src_ip,
                (unsigned)entry->key.src_port,
                entry->key.dst_ip,
                (unsigned)entry->key.dst_port,
                entry->workload[0] ? entry->workload : "-",
                (unsigned long long)entry->packets,
                bytes_human,
                (unsigned long long)entry->connections,
                (unsigned long long)flow_connections_effective(entry, is_final),
                flow_connection_inferred(entry) ? "yes" : "no",
                flow_tcp_seen_without_syn(entry, is_final) ? "yes" : "no"
            );
        }
    }

    jsonl_writer_write_flow(&app->writer, app->hostname, app->cfg.interface, entry, is_final,
                            app->cfg.include_identity_fields);
}

static int parse_l2_offset(const u_char *packet, size_t caplen, int linktype,
                           size_t *offset, uint16_t *ethertype) {
    *offset = 0;
    *ethertype = 0;

    /*
     * libpcap can expose different link-layer formats depending on interface
     * type and capture mode. We normalize them into a single L3 start offset so
     * the rest of the parser only cares about IPv4/IPv6 payloads.
     */
    if (linktype == DLT_EN10MB) {
        const struct ether_header *eth;
        if (caplen < sizeof(struct ether_header)) return 0;
        eth = (const struct ether_header *)packet;
        *offset = sizeof(struct ether_header);
        *ethertype = ntohs(eth->ether_type);
        return 1;
    }

    if (linktype == DLT_LINUX_SLL) {
        if (caplen < 16) return 0;
        *offset = 16;
        *ethertype = ((uint16_t)packet[14] << 8) | packet[15];
        return 1;
    }

    if (linktype == DLT_LINUX_SLL2) {
        if (caplen < 20) return 0;
        *offset = 20;
        *ethertype = ((uint16_t)packet[0] << 8) | packet[1];
        return 1;
    }

    if (linktype == DLT_RAW) {
        uint8_t version;
        if (caplen < 1) return 0;
        version = packet[0] >> 4;
        if (version == 4) {
            *ethertype = ETHERTYPE_IP;
            return 1;
        }
        if (version == 6) {
            *ethertype = ETHERTYPE_IPV6;
            return 1;
        }
    }

    return 0;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    size_t l2_offset = 0;
    uint16_t ethertype = 0;
    const uint8_t *l3;
    size_t l3len;
    flow_key_t key;
    flow_direction_t direction;
    int pid = -1;
    char process[IF_FLOW_MAX_PROC_NAME] = {0};
    char cmdline[IF_FLOW_MAX_CMDLINE] = {0};
    char workload[IF_FLOW_MAX_WORKLOAD] = {0};
    char sni[IF_FLOW_MAX_NAME] = {0};
    char host[IF_FLOW_MAX_NAME] = {0};
    const char *class_tag = "other";
    attr_source_t attr_source = ATTR_SRC_UNKNOWN;
    uint8_t proto = 0;
    size_t l4ofs = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    int new_connection = 0;

    (void)user;

    /*
     * Fast-path parser:
     * 1. Normalize L2 into an IPv4/IPv6 view.
     * 2. Extract a canonical 5-tuple.
     * 3. Derive optional metadata (SNI, Host, process identity).
     * 4. Update the in-memory flow accumulator.
     */
    if (!parse_l2_offset(packet, hdr->caplen, g_app.linktype, &l2_offset, &ethertype)) return;
    if (!(ethertype == ETHERTYPE_IP || ethertype == ETHERTYPE_IPV6)) return;

    l3 = packet + l2_offset;
    l3len = hdr->caplen - l2_offset;
    memset(&key, 0, sizeof(key));

    if (ethertype == ETHERTYPE_IP) {
        const struct ip *ip4;
        size_t ihl;
        if (l3len < sizeof(struct ip)) return;
        ip4 = (const struct ip *)l3;
        ihl = (size_t)ip4->ip_hl * 4;
        if (ihl < 20 || l3len < ihl) return;
        proto = ip4->ip_p;
        inet_ntop(AF_INET, &ip4->ip_src, key.src_ip, sizeof(key.src_ip));
        inet_ntop(AF_INET, &ip4->ip_dst, key.dst_ip, sizeof(key.dst_ip));
        l4ofs = ihl;
    } else {
        const struct ip6_hdr *ip6;
        if (l3len < sizeof(struct ip6_hdr)) return;
        ip6 = (const struct ip6_hdr *)l3;
        proto = ip6->ip6_nxt;
        inet_ntop(AF_INET6, &ip6->ip6_src, key.src_ip, sizeof(key.src_ip));
        inet_ntop(AF_INET6, &ip6->ip6_dst, key.dst_ip, sizeof(key.dst_ip));
        l4ofs = sizeof(struct ip6_hdr);
    }

    if (!(proto == IPPROTO_TCP || proto == IPPROTO_UDP)) return;
    if (l3len < l4ofs + 8) return;

    key.proto = proto;
    if (proto == IPPROTO_TCP) {
        const struct tcphdr *tcp;
        size_t doff;
        if (l3len < l4ofs + sizeof(struct tcphdr)) return;
        tcp = (const struct tcphdr *)(l3 + l4ofs);
        key.src_port = ntohs(tcp->th_sport);
        key.dst_port = ntohs(tcp->th_dport);
        doff = (size_t)tcp->th_off * 4;
        if (doff < 20 || l3len < l4ofs + doff) return;
        payload = l3 + l4ofs + doff;
        payload_len = l3len - l4ofs - doff;
        if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK)) new_connection = 1;
    } else {
        const struct udphdr *udp;
        if (l3len < l4ofs + sizeof(struct udphdr)) return;
        udp = (const struct udphdr *)(l3 + l4ofs);
        key.src_port = ntohs(udp->uh_sport);
        key.dst_port = ntohs(udp->uh_dport);
        payload = l3 + l4ofs + sizeof(struct udphdr);
        payload_len = l3len - l4ofs - sizeof(struct udphdr);
        new_connection = 1;
    }

    /*
     * We only inspect enough application payload to enrich the record with a
     * name. Packets themselves are not stored, and payload bytes are discarded
     * immediately after SNI/Host extraction.
     */
    if (proto == IPPROTO_TCP && payload && payload_len > 0) {
        if (key.src_port == 443 || key.dst_port == 443) {
            parser_extract_tls_sni(payload, payload_len, sni, sizeof(sni));
        }
        parser_extract_http_host(payload, payload_len, host, sizeof(host));
    }

    direction = detect_direction(key.src_ip, key.dst_ip);
    /*
     * Attribution order matters:
     * - eBPF gives the freshest socket-to-process hint when available.
     * - /proc resolver is a slower fallback for cases eBPF did not cover.
     */
    if (g_app.cfg.use_ebpf && ebpf_tracker_lookup(&g_app.ebpf, &key, &pid, process, sizeof(process))) {
        resolver_read_identity_by_pid(pid, process, sizeof(process), cmdline, sizeof(cmdline), workload, sizeof(workload));
        if (workload[0] == '\0') snprintf(workload, sizeof(workload), "HOST");
        attr_source = ATTR_SRC_EBPF;
    } else if (resolver_lookup(&g_app.resolver, &key, &pid, process, sizeof(process), cmdline, sizeof(cmdline), workload, sizeof(workload))) {
        attr_source = ATTR_SRC_PROC;
    }
    class_tag = classify_flow(&key, sni, host);
    /*
     * The flow table owns minute-bucket aggregation. From this point on we only
     * retain counters and derived metadata, not the raw packet contents.
     */
    flow_table_touch(&g_app.flows, &key, direction, pid, process, cmdline, workload, sni, host, class_tag, attr_source,
                     (uint64_t)hdr->caplen, new_connection, now_sec());
}

static int run_selftest(void) {
    flow_key_t key1;
    flow_key_t key2;
    flow_key_t key3;
    flow_key_t key4;
    double base = 1719000000.0;
    char sni[IF_FLOW_MAX_NAME];
    char host[IF_FLOW_MAX_NAME];
    uint8_t tls_client_hello[72];
    const char http_req[] = "GET / HTTP/1.1\r\nHost: api.example.org\r\nUser-Agent: test\r\n\r\n";

    memset(&key1, 0, sizeof(key1));
    memset(&key2, 0, sizeof(key2));
    memset(&key3, 0, sizeof(key3));
    memset(&key4, 0, sizeof(key4));
    memset(sni, 0, sizeof(sni));
    memset(host, 0, sizeof(host));
    memset(tls_client_hello, 0, sizeof(tls_client_hello));

    tls_client_hello[0] = 0x16;
    tls_client_hello[1] = 0x03;
    tls_client_hello[2] = 0x01;
    tls_client_hello[5] = 0x01;
    tls_client_hello[9] = 0x03;
    tls_client_hello[10] = 0x03;
    tls_client_hello[43] = 0x00;
    tls_client_hello[44] = 0x00;
    tls_client_hello[45] = 0x02;
    tls_client_hello[46] = 0x13;
    tls_client_hello[47] = 0x01;
    tls_client_hello[48] = 0x01;
    tls_client_hello[49] = 0x00;
    tls_client_hello[50] = 0x00;
    tls_client_hello[51] = 0x14;
    tls_client_hello[52] = 0x00;
    tls_client_hello[53] = 0x00;
    tls_client_hello[54] = 0x00;
    tls_client_hello[55] = 0x10;
    tls_client_hello[56] = 0x00;
    tls_client_hello[57] = 0x0e;
    tls_client_hello[58] = 0x00;
    tls_client_hello[59] = 0x00;
    tls_client_hello[60] = 0x0b;
    memcpy(&tls_client_hello[61], "example.org", 11);

    snprintf(g_app.hostname, sizeof(g_app.hostname), "selftest-host");

    snprintf(key1.src_ip, sizeof(key1.src_ip), "10.0.0.10");
    snprintf(key1.dst_ip, sizeof(key1.dst_ip), "1.1.1.1");
    key1.proto = IPPROTO_TCP;
    key1.src_port = 43210;
    key1.dst_port = 443;

    snprintf(key2.src_ip, sizeof(key2.src_ip), "192.168.1.50");
    snprintf(key2.dst_ip, sizeof(key2.dst_ip), "10.0.0.20");
    key2.proto = IPPROTO_UDP;
    key2.src_port = 53000;
    key2.dst_port = 53;

    snprintf(key3.src_ip, sizeof(key3.src_ip), "10.0.0.30");
    snprintf(key3.dst_ip, sizeof(key3.dst_ip), "10.0.0.40");
    key3.proto = IPPROTO_TCP;
    key3.src_port = 55000;
    key3.dst_port = 5432;

    snprintf(key4.src_ip, sizeof(key4.src_ip), "10.0.0.50");
    snprintf(key4.dst_ip, sizeof(key4.dst_ip), "239.255.255.250");
    key4.proto = IPPROTO_UDP;
    key4.src_port = 40000;
    key4.dst_port = 1900;

    flow_key_t key5 = {0};
    snprintf(key5.src_ip, sizeof(key5.src_ip), "10.0.0.50");
    snprintf(key5.dst_ip, sizeof(key5.dst_ip), "10.0.0.60");
    key5.proto = IPPROTO_TCP;
    key5.src_port = 50123;
    key5.dst_port = 8123;

    flow_key_t key6 = {0};
    snprintf(key6.src_ip, sizeof(key6.src_ip), "10.0.0.50");
    snprintf(key6.dst_ip, sizeof(key6.dst_ip), "8.8.8.8");
    key6.proto = IPPROTO_UDP;
    key6.src_port = 50124;
    key6.dst_port = 443;

    if (!parser_extract_tls_sni(tls_client_hello, sizeof(tls_client_hello), sni, sizeof(sni))) {
        fprintf(stderr, "selftest: failed to parse TLS SNI\n");
        return 1;
    }
    if (strcmp(sni, "example.org") != 0) {
        fprintf(stderr, "selftest: unexpected SNI: %s\n", sni);
        return 1;
    }
    if (!parser_extract_http_host((const uint8_t *)http_req, strlen(http_req), host, sizeof(host))) {
        fprintf(stderr, "selftest: failed to parse HTTP Host\n");
        return 1;
    }
    if (strcmp(host, "api.example.org") != 0) {
        fprintf(stderr, "selftest: unexpected Host: %s\n", host);
        return 1;
    }
    if (strcmp(classify_flow(&key3, "", ""), "postgres") != 0) {
        fprintf(stderr, "selftest: expected postgres class\n");
        return 1;
    }
    if (strcmp(classify_flow(&key4, "", ""), "ssdp") != 0) {
        fprintf(stderr, "selftest: expected ssdp class\n");
        return 1;
    }
    if (strcmp(classify_flow(&key5, "", ""), "clickhouse") != 0) {
        fprintf(stderr, "selftest: expected clickhouse class\n");
        return 1;
    }
    if (strcmp(classify_flow(&key6, "", ""), "quic") != 0) {
        fprintf(stderr, "selftest: expected quic class\n");
        return 1;
    }

    flow_table_touch(&g_app.flows, &key1, FLOW_DIR_OUT, 1234, "curl", "curl https://example.org", "HOST", sni, "", "named_app", ATTR_SRC_EBPF, 120, 1, base);
    flow_table_touch(&g_app.flows, &key1, FLOW_DIR_OUT, 1234, "curl", "curl https://example.org", "HOST", sni, "", "named_app", ATTR_SRC_EBPF, 120, 1, base + 0.2);
    flow_table_touch(&g_app.flows, &key1, FLOW_DIR_OUT, 1234, "curl", "curl https://example.org", "HOST", sni, "", "named_app", ATTR_SRC_EBPF, 380, 0, base + 1.0);
    flow_table_touch(&g_app.flows, &key2, FLOW_DIR_IN, -1, "", "", "", "", host, "dns", ATTR_SRC_UNKNOWN, 90, 1, base + 2.0);

    flow_table_emit_ready(&g_app.flows, 1.0, base + 3.0, flush_flow_entry, &g_app);
    flow_table_flush_older_than(&g_app.flows, minute_bucket_for(base + 60.0), flush_flow_entry, &g_app);
    return 0;
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    int rc;
    double last_flush;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    config_set_defaults(&g_app.cfg);
    rc = config_parse_args(&g_app.cfg, argc, argv);
    if (rc != 0) return (rc > 0) ? 0 : 1;

    gethostname(g_app.hostname, sizeof(g_app.hostname));
    g_app.hostname[sizeof(g_app.hostname) - 1] = '\0';
    local_ip_list_init(&g_app.local_ips);
    flow_table_init(&g_app.flows, (size_t)g_app.cfg.max_flows);
    ebpf_tracker_init(&g_app.ebpf, g_app.cfg.ebpf_ttl_sec, g_app.cfg.datapath_ttl_sec,
                      g_app.cfg.use_datapath, g_app.cfg.bpf_object);
    resolver_init(&g_app.resolver, g_app.cfg.resolver_ttl_sec, g_app.cfg.resolver_refresh_sec);
    if (jsonl_writer_open(&g_app.writer, g_app.cfg.json_path, g_app.cfg.json_max_file_size_bytes) != 0) {
        fprintf(stderr, "failed to open json output: %s\n", g_app.cfg.json_path);
        flow_table_free(&g_app.flows);
        ebpf_tracker_close(&g_app.ebpf);
        local_ip_list_free(&g_app.local_ips);
        return 1;
    }

    if (g_app.cfg.selftest) {
        rc = run_selftest();
        jsonl_writer_close(&g_app.writer);
        flow_table_free(&g_app.flows);
        ebpf_tracker_close(&g_app.ebpf);
        resolver_free(&g_app.resolver);
        local_ip_list_free(&g_app.local_ips);
        return rc;
    }

    if (local_ip_list_load(&g_app.local_ips) != 0) {
        fprintf(stderr, "warning: failed to load local IP list, direction may be incomplete\n");
    }

    if (g_app.cfg.use_ebpf) {
        if (ebpf_tracker_open(&g_app.ebpf) != 0) {
            fprintf(stderr, "warning: eBPF init failed, continuing with /proc resolver only\n");
            g_app.cfg.use_ebpf = 0;
            ebpf_tracker_close(&g_app.ebpf);
        }
    }

    pcap_handle = pcap_open_live(g_app.cfg.interface, 262144, 1, 100, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        jsonl_writer_close(&g_app.writer);
        flow_table_free(&g_app.flows);
        ebpf_tracker_close(&g_app.ebpf);
        resolver_free(&g_app.resolver);
        local_ip_list_free(&g_app.local_ips);
        return 1;
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
        fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    }

    g_app.linktype = pcap_datalink(pcap_handle);
    last_flush = now_sec();

    printf("Starting if_flow on interface: %s\n", g_app.cfg.interface);
    printf("Press Ctrl+C to stop.\n");
    fflush(stdout);

    while (!g_stop) {
        int dispatch_rc;
        double now;

        dispatch_rc = pcap_dispatch(pcap_handle, 128, packet_handler, NULL);
        if (dispatch_rc == -1) {
            fprintf(stderr, "pcap_dispatch failed: %s\n", pcap_geterr(pcap_handle));
            break;
        }

        if (g_app.cfg.use_ebpf) {
            int ebpf_rc = ebpf_tracker_poll(&g_app.ebpf, dispatch_rc > 0 ? 0 : 5);
            if (ebpf_rc < 0) {
                fprintf(stderr, "warning: eBPF poll failed: %d\n", ebpf_rc);
            }
        }

        now = now_sec();
        flow_table_emit_ready(&g_app.flows, (double)g_app.cfg.stream_flush_sec, now, flush_flow_entry, &g_app);
        if ((now - last_flush) >= g_app.cfg.minute_flush_sec) {
            flow_table_flush_older_than(&g_app.flows, minute_bucket_for(now), flush_flow_entry, &g_app);
            last_flush = now;
        }

        if (dispatch_rc == 0) usleep(5000);
    }

    flow_table_flush_older_than(&g_app.flows, minute_bucket_for(now_sec() + 60.0), flush_flow_entry, &g_app);
    pcap_close(pcap_handle);
    jsonl_writer_close(&g_app.writer);
    flow_table_free(&g_app.flows);
    ebpf_tracker_close(&g_app.ebpf);
    resolver_free(&g_app.resolver);
    local_ip_list_free(&g_app.local_ips);
    return 0;
}
