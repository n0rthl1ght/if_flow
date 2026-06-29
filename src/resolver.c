#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "resolver.h"

typedef struct {
    uint8_t proto;
    char src_ip[IF_FLOW_MAX_IP_STR];
    uint16_t src_port;
    char dst_ip[IF_FLOW_MAX_IP_STR];
    uint16_t dst_port;
    char inode[64];
} proc_conn_t;

typedef struct {
    char inode[64];
    int pid;
} inode_owner_t;

typedef struct {
    int pid;
    char process[IF_FLOW_MAX_PROC_NAME];
    char cmdline[IF_FLOW_MAX_CMDLINE];
    char workload[IF_FLOW_MAX_WORKLOAD];
    double ts;
} pid_identity_cache_entry_t;

static pid_identity_cache_entry_t g_pid_cache[1024];

/* /proc scanning is expensive, so PID identity lookups get their own tiny cache. */
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int is_digits(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    if (!s || !*s) return 0;
    while (*p) {
        if (!isdigit(*p)) return 0;
        ++p;
    }
    return 1;
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

static int is_pid_placeholder_name(const char *name) {
    const unsigned char *p;
    if (!name) return 0;
    if (strncmp(name, "pid_", 4) != 0) return 0;
    p = (const unsigned char *)(name + 4);
    if (!*p) return 0;
    while (*p) {
        if (!isdigit(*p)) return 0;
        ++p;
    }
    return 1;
}

/* Drop stale flow-to-PID cache entries after the configured TTL window. */
static void resolver_cache_prune(resolver_t *resolver) {
    size_t r;
    size_t w = 0;
    double cutoff;
    if (!resolver) return;
    cutoff = now_sec() - resolver->ttl_sec;
    for (r = 0; r < resolver->len; ++r) {
        if (resolver->entries[r].ts >= cutoff) {
            if (w != r) resolver->entries[w] = resolver->entries[r];
            ++w;
        }
    }
    resolver->len = w;
}

static void resolver_cache_put(resolver_t *resolver, const flow_key_t *key,
                               int pid, const char *process, const char *cmdline, const char *workload) {
    size_t i;
    if (!resolver || !key || pid < 0) return;
    /* Refresh an existing cached match before allocating more entries. */
    for (i = 0; i < resolver->len; ++i) {
        if (flow_key_equal(&resolver->entries[i].key, key)) {
            resolver->entries[i].pid = pid;
            safe_copy(resolver->entries[i].process, sizeof(resolver->entries[i].process), process);
            safe_copy(resolver->entries[i].cmdline, sizeof(resolver->entries[i].cmdline), cmdline);
            safe_copy(resolver->entries[i].workload, sizeof(resolver->entries[i].workload), workload);
            resolver->entries[i].ts = now_sec();
            return;
        }
    }
    if (resolver->len == resolver->cap) {
        size_t new_cap = resolver->cap ? resolver->cap * 2 : 2048;
        resolver_cache_entry_t *new_entries =
            (resolver_cache_entry_t *)realloc(resolver->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) return;
        resolver->entries = new_entries;
        resolver->cap = new_cap;
    }
    resolver->entries[resolver->len].key = *key;
    resolver->entries[resolver->len].pid = pid;
    safe_copy(resolver->entries[resolver->len].process, sizeof(resolver->entries[resolver->len].process), process);
    safe_copy(resolver->entries[resolver->len].cmdline, sizeof(resolver->entries[resolver->len].cmdline), cmdline);
    safe_copy(resolver->entries[resolver->len].workload, sizeof(resolver->entries[resolver->len].workload), workload);
    resolver->entries[resolver->len].ts = now_sec();
    resolver->len++;
    resolver_cache_prune(resolver);
}

static int resolver_cache_get(resolver_t *resolver, const flow_key_t *key,
                              int *pid, char *process, size_t process_sz,
                              char *cmdline, size_t cmdline_sz,
                              char *workload, size_t workload_sz) {
    ssize_t i;
    double cutoff;
    if (!resolver || !key || !pid || !process || !cmdline || !workload) return 0;
    cutoff = now_sec() - resolver->ttl_sec;
    /*
     * Reverse lookup favors the newest mapping first and also accepts the
     * reverse 5-tuple because inbound traffic may be checked after an outbound
     * socket was discovered in /proc.
     */
    for (i = (ssize_t)resolver->len - 1; i >= 0; --i) {
        if (resolver->entries[i].ts < cutoff) break;
        if (!flow_key_equal(&resolver->entries[i].key, key) &&
            !flow_key_equal_rev(&resolver->entries[i].key, key)) continue;
        *pid = resolver->entries[i].pid;
        safe_copy(process, process_sz, resolver->entries[i].process);
        safe_copy(cmdline, cmdline_sz, resolver->entries[i].cmdline);
        safe_copy(workload, workload_sz, resolver->entries[i].workload);
        return 1;
    }
    return 0;
}

static int decode_ipv4_proc(const char *hex, char *out, size_t out_sz) {
    unsigned int b[4];
    if (!hex || strlen(hex) < 8) return -1;
    if (sscanf(hex, "%2x%2x%2x%2x", &b[3], &b[2], &b[1], &b[0]) != 4) return -1;
    snprintf(out, out_sz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return 0;
}

/* /proc/net/tcp6 and udp6 expose IPv6 addresses in kernel-endian hex form. */
static int decode_ipv6_proc(const char *hex, char *out, size_t out_sz) {
    uint32_t p[4];
    uint8_t bytes[16];
    int i;
    if (!hex || strlen(hex) < 32) return -1;
    if (sscanf(hex, "%8x%8x%8x%8x", &p[0], &p[1], &p[2], &p[3]) != 4) return -1;
    for (i = 0; i < 4; ++i) {
        uint32_t v = p[i];
        bytes[i * 4 + 0] = (uint8_t)(v & 0xff);
        bytes[i * 4 + 1] = (uint8_t)((v >> 8) & 0xff);
        bytes[i * 4 + 2] = (uint8_t)((v >> 16) & 0xff);
        bytes[i * 4 + 3] = (uint8_t)((v >> 24) & 0xff);
    }
    if (!inet_ntop(AF_INET6, bytes, out, out_sz)) return -1;
    return 0;
}

static void read_comm(int pid, char *process, size_t process_sz) {
    char path[128];
    FILE *fp;
    size_t len;
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fp = fopen(path, "r");
    if (!fp) {
        snprintf(process, process_sz, "pid_%d", pid);
        return;
    }
    if (!fgets(process, (int)process_sz, fp)) snprintf(process, process_sz, "pid_%d", pid);
    fclose(fp);
    len = strlen(process);
    while (len > 0 && (process[len - 1] == '\n' || process[len - 1] == '\r')) process[--len] = '\0';
}

static void read_cmdline(int pid, char *cmdline, size_t cmdline_sz) {
    char path[128];
    FILE *fp;
    size_t n;
    size_t i;
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fp = fopen(path, "rb");
    if (!fp) {
        safe_copy(cmdline, cmdline_sz, "");
        return;
    }
    n = fread(cmdline, 1, cmdline_sz - 1, fp);
    fclose(fp);
    cmdline[n] = '\0';
    for (i = 0; i < n; ++i) if (cmdline[i] == '\0') cmdline[i] = ' ';
}

static void workload_for_pid(int pid, char *buf, size_t buf_sz) {
    char path[128];
    FILE *fp;
    size_t n;
    char text[8192];
    char lower[8192];
    size_t i;
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    fp = fopen(path, "r");
    if (!fp) {
        snprintf(buf, buf_sz, "HOST");
        return;
    }
    n = fread(text, 1, sizeof(text) - 1, fp);
    fclose(fp);
    text[n] = '\0';
    for (i = 0; i < n; ++i) lower[i] = (char)tolower((unsigned char)text[i]);
    lower[n] = '\0';
    /*
     * Workload classification stays intentionally coarse. It is meant to tell
     * apart host, Docker, and Kubernetes/containerized activity for analytics.
     */
    if (strstr(lower, "kubepods")) snprintf(buf, buf_sz, "K8S");
    else if (strstr(lower, "docker")) snprintf(buf, buf_sz, "DOCKER");
    else if (strstr(lower, "containerd") || strstr(lower, "crio")) snprintf(buf, buf_sz, "CONTAINER");
    else snprintf(buf, buf_sz, "HOST");
}

void resolver_read_identity_by_pid(int pid, char *process, size_t process_sz,
                                   char *cmdline, size_t cmdline_sz,
                                   char *workload, size_t workload_sz) {
    size_t idx;
    double cutoff;
    char original_process[IF_FLOW_MAX_PROC_NAME];
    char comm_tmp[IF_FLOW_MAX_PROC_NAME];
    if (pid < 0) {
        safe_copy(process, process_sz, "");
        safe_copy(cmdline, cmdline_sz, "");
        safe_copy(workload, workload_sz, "");
        return;
    }
    /*
     * A tiny direct-mapped cache is enough here because repeated packets often
     * hit the same few PIDs over short periods. This saves repeated reads of
     * /proc/<pid>/comm, cmdline, and cgroup.
     */
    idx = (size_t)pid % (sizeof(g_pid_cache) / sizeof(g_pid_cache[0]));
    cutoff = now_sec() - 30.0;
    if (g_pid_cache[idx].pid == pid && g_pid_cache[idx].ts >= cutoff) {
        safe_copy(process, process_sz, g_pid_cache[idx].process);
        safe_copy(cmdline, cmdline_sz, g_pid_cache[idx].cmdline);
        safe_copy(workload, workload_sz, g_pid_cache[idx].workload);
        return;
    }

    safe_copy(original_process, sizeof(original_process), process);
    read_comm(pid, comm_tmp, sizeof(comm_tmp));
    if (is_pid_placeholder_name(comm_tmp) && original_process[0]) {
        safe_copy(process, process_sz, original_process);
    } else {
        safe_copy(process, process_sz, comm_tmp);
    }
    read_cmdline(pid, cmdline, cmdline_sz);
    workload_for_pid(pid, workload, workload_sz);

    g_pid_cache[idx].pid = pid;
    safe_copy(g_pid_cache[idx].process, sizeof(g_pid_cache[idx].process), process);
    safe_copy(g_pid_cache[idx].cmdline, sizeof(g_pid_cache[idx].cmdline), cmdline);
    safe_copy(g_pid_cache[idx].workload, sizeof(g_pid_cache[idx].workload), workload);
    g_pid_cache[idx].ts = now_sec();
}

static size_t parse_proc_net_file(const char *path, int is_v6, uint8_t proto,
                                  proc_conn_t *conns, size_t max_conns) {
    FILE *fp;
    char line[1024];
    size_t len = 0;
    fp = fopen(path, "r");
    if (!fp) return 0;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }
    /*
     * Parse kernel socket tables into canonical flow keys plus socket inode.
     * Ownership is resolved in a second phase by walking /proc/<pid>/fd links.
     */
    while (fgets(line, sizeof(line), fp) && len < max_conns) {
        char *parts[32];
        int np = 0;
        char *save = NULL;
        char *tok = strtok_r(line, " \t\r\n", &save);
        char local_buf[128];
        char remote_buf[128];
        char *c1;
        char *c2;
        char ip1[IF_FLOW_MAX_IP_STR];
        char ip2[IF_FLOW_MAX_IP_STR];
        unsigned int p1;
        unsigned int p2;

        while (tok && np < (int)(sizeof(parts) / sizeof(parts[0]))) {
            parts[np++] = tok;
            tok = strtok_r(NULL, " \t\r\n", &save);
        }
        if (np < 10) continue;
        safe_copy(local_buf, sizeof(local_buf), parts[1]);
        safe_copy(remote_buf, sizeof(remote_buf), parts[2]);
        c1 = strchr(local_buf, ':');
        c2 = strchr(remote_buf, ':');
        if (!c1 || !c2) continue;
        *c1 = '\0';
        *c2 = '\0';
        if (!is_v6) {
            if (decode_ipv4_proc(local_buf, ip1, sizeof(ip1)) != 0) continue;
            if (decode_ipv4_proc(remote_buf, ip2, sizeof(ip2)) != 0) continue;
        } else {
            if (decode_ipv6_proc(local_buf, ip1, sizeof(ip1)) != 0) continue;
            if (decode_ipv6_proc(remote_buf, ip2, sizeof(ip2)) != 0) continue;
        }
        if (sscanf(c1 + 1, "%x", &p1) != 1) continue;
        if (sscanf(c2 + 1, "%x", &p2) != 1) continue;

        conns[len].proto = proto;
        safe_copy(conns[len].src_ip, sizeof(conns[len].src_ip), ip1);
        safe_copy(conns[len].dst_ip, sizeof(conns[len].dst_ip), ip2);
        conns[len].src_port = (uint16_t)p1;
        conns[len].dst_port = (uint16_t)p2;
        safe_copy(conns[len].inode, sizeof(conns[len].inode), parts[9]);
        ++len;
    }
    fclose(fp);
    return len;
}

static size_t collect_inode_owners(inode_owner_t *owners, size_t max_owners) {
    DIR *dp;
    struct dirent *de;
    size_t len = 0;
    dp = opendir("/proc");
    if (!dp) return 0;
    /*
     * This is the expensive half of the fallback resolver: enumerate process
     * file descriptors and map socket:[inode] links back to owning PIDs.
     */
    while ((de = readdir(dp)) && len < max_owners) {
        int pid;
        char fd_dir[128];
        DIR *fdp;
        struct dirent *fde;
        if (!is_digits(de->d_name)) continue;
        pid = atoi(de->d_name);
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
        fdp = opendir(fd_dir);
        if (!fdp) continue;
        while ((fde = readdir(fdp)) && len < max_owners) {
            char fp[1024];
            char linkv[1024];
            ssize_t ln;
            char *s;
            char *e;
            if (fde->d_name[0] == '.') continue;
            snprintf(fp, sizeof(fp), "%s/%s", fd_dir, fde->d_name);
            ln = readlink(fp, linkv, sizeof(linkv) - 1);
            if (ln <= 0) continue;
            linkv[ln] = '\0';
            if (strncmp(linkv, "socket:[", 8) != 0) continue;
            s = linkv + 8;
            e = strchr(s, ']');
            if (!e) continue;
            *e = '\0';
            safe_copy(owners[len].inode, sizeof(owners[len].inode), s);
            owners[len].pid = pid;
            ++len;
        }
        closedir(fdp);
    }
    closedir(dp);
    return len;
}

static int lookup_inode_owner(const inode_owner_t *owners, size_t owners_len,
                              const char *inode, int *pid) {
    size_t i;
    for (i = 0; i < owners_len; ++i) {
        if (strcmp(owners[i].inode, inode) == 0) {
            *pid = owners[i].pid;
            return 1;
        }
    }
    return 0;
}

void resolver_init(resolver_t *resolver, double ttl_sec, double refresh_sec) {
    if (!resolver) return;
    memset(resolver, 0, sizeof(*resolver));
    resolver->ttl_sec = ttl_sec;
    resolver->refresh_sec = refresh_sec;
}

void resolver_free(resolver_t *resolver) {
    if (!resolver) return;
    free(resolver->entries);
    resolver->entries = NULL;
    resolver->len = 0;
    resolver->cap = 0;
}

int resolver_lookup(resolver_t *resolver, const flow_key_t *key,
                    int *pid, char *process, size_t process_sz,
                    char *cmdline, size_t cmdline_sz,
                    char *workload, size_t workload_sz) {
    proc_conn_t conns[16384];
    inode_owner_t owners[32768];
    size_t conns_len = 0;
    size_t owners_len;
    size_t i;
    double now;

    if (!resolver || !key || !pid || !process || !cmdline || !workload) return 0;
    *pid = -1;
    safe_copy(process, process_sz, "");
    safe_copy(cmdline, cmdline_sz, "");
    safe_copy(workload, workload_sz, "");

    /* Fast path: serve recent answers from the in-memory cache. */
    if (resolver_cache_get(resolver, key, pid, process, process_sz, cmdline, cmdline_sz, workload, workload_sz)) {
        return 1;
    }

    now = now_sec();
    /* Throttle cache misses so high packet rates do not trigger nonstop /proc scans. */
    if ((now - resolver->last_refresh) < resolver->refresh_sec) return 0;
    resolver->last_refresh = now;

    conns_len += parse_proc_net_file("/proc/net/tcp", 0, IPPROTO_TCP, conns + conns_len, 16384 - conns_len);
    conns_len += parse_proc_net_file("/proc/net/tcp6", 1, IPPROTO_TCP, conns + conns_len, 16384 - conns_len);
    conns_len += parse_proc_net_file("/proc/net/udp", 0, IPPROTO_UDP, conns + conns_len, 16384 - conns_len);
    conns_len += parse_proc_net_file("/proc/net/udp6", 1, IPPROTO_UDP, conns + conns_len, 16384 - conns_len);
    owners_len = collect_inode_owners(owners, 32768);

    /*
     * Match the target flow against the current kernel socket snapshot, then
     * translate socket inode to PID and finally enrich that PID into identity
     * fields suitable for JSONL and ClickHouse output.
     */
    for (i = 0; i < conns_len; ++i) {
        flow_key_t candidate;
        int owner_pid;
        memset(&candidate, 0, sizeof(candidate));
        candidate.proto = conns[i].proto;
        safe_copy(candidate.src_ip, sizeof(candidate.src_ip), conns[i].src_ip);
        safe_copy(candidate.dst_ip, sizeof(candidate.dst_ip), conns[i].dst_ip);
        candidate.src_port = conns[i].src_port;
        candidate.dst_port = conns[i].dst_port;
        if (!flow_key_equal(&candidate, key) &&
            !flow_key_equal_rev(&candidate, key)) continue;
        if (!lookup_inode_owner(owners, owners_len, conns[i].inode, &owner_pid)) continue;
        *pid = owner_pid;
        resolver_read_identity_by_pid(owner_pid, process, process_sz, cmdline, cmdline_sz, workload, workload_sz);
        resolver_cache_put(resolver, key, *pid, process, cmdline, workload);
        return 1;
    }

    return 0;
}
