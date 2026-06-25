#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "writer_jsonl.h"

/*
 * JSONL is our interchange format for both local troubleshooting and the
 * ClickHouse uploader. Non-ASCII bytes are escaped deliberately so partially
 * invalid process names or command lines never break downstream JSON parsing.
 */
static void json_escape(FILE *fp, const char *s) {
    const unsigned char *p;
    fputc('"', fp);
    for (p = (const unsigned char *)s; p && *p; ++p) {
        switch (*p) {
            case '"': fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if (*p < 0x20 || *p >= 0x80) fprintf(fp, "\\u%04x", *p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static void split_base_ext(const char *base, char *stem, size_t stem_sz, char *ext, size_t ext_sz) {
    const char *dot;
    size_t n;
    if (!base || !*base) {
        snprintf(stem, stem_sz, "if_flow");
        snprintf(ext, ext_sz, ".jsonl");
        return;
    }
    dot = strrchr(base, '.');
    if (!dot || dot == base) {
        snprintf(stem, stem_sz, "%s", base);
        ext[0] = '\0';
        return;
    }
    n = (size_t)(dot - base);
    if (n >= stem_sz) n = stem_sz - 1;
    memcpy(stem, base, n);
    stem[n] = '\0';
    snprintf(ext, ext_sz, "%s", dot);
}

static void get_local_day(char *out, size_t out_sz) {
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(out, out_sz, "%Y-%m-%d", &tmv);
}

static void build_active_path(char *out, size_t out_sz, const char *stem, const char *day,
                              const char *ext, int index) {
    if (index <= 0) snprintf(out, out_sz, "%s-%s%s", stem, day, ext);
    else snprintf(out, out_sz, "%s-%s-%04d%s", stem, day, index, ext);
}

static int stat_size(const char *path, off_t *size_out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (size_out) *size_out = st.st_size;
    return 0;
}

static int choose_active_index(const jsonl_writer_t *writer, const char *day,
                               const char *stem, const char *ext) {
    int idx = 0;
    char path[1200];
    off_t size = 0;

    if (!writer || writer->max_file_size_bytes == 0) return 0;

    /*
     * Reuse the first file for the current day that is still below the size
     * limit. Once every existing chunk is full we advance to the next suffix.
     */
    for (;;) {
        build_active_path(path, sizeof(path), stem, day, ext, idx);
        if (stat_size(path, &size) != 0) {
            if (idx == 0) return 0;
            return idx;
        }
        if ((size_t)size < writer->max_file_size_bytes) return idx;
        ++idx;
    }
}

static void format_minute_iso(uint64_t minute_bucket, char *out, size_t out_sz) {
    time_t tt = (time_t)minute_bucket;
    struct tm tmv;
    localtime_r(&tt, &tmv);
    strftime(out, out_sz, "%Y-%m-%dT%H:%M:00%z", &tmv);
}

static void format_time_iso(double ts, char *out, size_t out_sz) {
    time_t tt = (time_t)ts;
    struct tm tmv;
    localtime_r(&tt, &tmv);
    strftime(out, out_sz, "%Y-%m-%dT%H:%M:%S%z", &tmv);
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

static int flow_connection_inferred(const flow_entry_t *entry) {
    if (!entry) return 0;
    return entry->key.proto == 6 && entry->packets > 0 && entry->connections == 0;
}

/*
 * Packet capture can miss the initial SYN, especially when the agent starts on
 * an already active host or when capture begins after a flow is established.
 * For final TCP records we therefore expose a soft flag that says "traffic was
 * clearly present, but the formal connection opener was never observed".
 */
static int flow_tcp_seen_without_syn(const flow_entry_t *entry, int is_final) {
    if (!entry || !is_final) return 0;
    if (entry->key.proto != 6) return 0;
    if (entry->packets == 0) return 0;
    if (entry->connections != 0) return 0;
    return entry->attr_source == ATTR_SRC_EBPF || entry->attr_source == ATTR_SRC_PROC;
}

static uint64_t flow_connections_effective(const flow_entry_t *entry, int is_final) {
    if (!entry) return 0;
    if (flow_tcp_seen_without_syn(entry, is_final)) return 1;
    return entry->connections;
}

static int jsonl_writer_rotate_if_needed(jsonl_writer_t *writer) {
    char day[16];
    char stem[1024];
    char ext[128];
    char path[1200];
    off_t size = 0;
    int wanted_index;
    if (!writer || !writer->base_path[0]) return -1;
    get_local_day(day, sizeof(day));
    split_base_ext(writer->base_path, stem, sizeof(stem), ext, sizeof(ext));

    wanted_index = choose_active_index(writer, day, stem, ext);
    build_active_path(path, sizeof(path), stem, day, ext, wanted_index);

    /*
     * Keep writing to the existing file as long as both rotation dimensions
     * still match: same local day and same size bucket.
     */
    if (writer->fp && strcmp(writer->active_day, day) == 0 &&
        writer->active_index == wanted_index &&
        strcmp(writer->active_path, path) == 0) {
        if (writer->max_file_size_bytes == 0) return 0;
        if (stat_size(writer->active_path, &size) == 0 &&
            (size_t)size < writer->max_file_size_bytes) return 0;
    }

    /* A day rollover or size threshold switch reopens the writer on a new path. */
    if (writer->fp) fclose(writer->fp);
    writer->fp = fopen(path, "a");
    if (!writer->fp) return -1;
    snprintf(writer->active_day, sizeof(writer->active_day), "%s", day);
    snprintf(writer->active_path, sizeof(writer->active_path), "%s", path);
    writer->active_index = wanted_index;
    return 0;
}

int jsonl_writer_open(jsonl_writer_t *writer, const char *path, size_t max_file_size_bytes) {
    if (!writer || !path || !*path) return -1;
    memset(writer, 0, sizeof(*writer));
    snprintf(writer->base_path, sizeof(writer->base_path), "%s", path);
    writer->max_file_size_bytes = max_file_size_bytes;
    return jsonl_writer_rotate_if_needed(writer);
}

void jsonl_writer_close(jsonl_writer_t *writer) {
    if (!writer) return;
    if (writer->fp) fclose(writer->fp);
    writer->fp = NULL;
}

void jsonl_writer_write_flow(jsonl_writer_t *writer, const char *host, const char *iface,
                             const flow_entry_t *entry, int is_final, int include_identity_fields) {
    FILE *fp;
    char minute_iso[40];
    char bytes_human[32];
    char first_seen_iso[40];
    char last_seen_iso[40];
    if (!writer || !entry) return;
    if (jsonl_writer_rotate_if_needed(writer) != 0) return;
    if (!writer->fp) return;
    fp = writer->fp;
    format_minute_iso(entry->minute_bucket, minute_iso, sizeof(minute_iso));
    format_bytes_human(entry->bytes, bytes_human, sizeof(bytes_human));
    format_time_iso(entry->first_seen, first_seen_iso, sizeof(first_seen_iso));
    format_time_iso(entry->last_seen, last_seen_iso, sizeof(last_seen_iso));

    /*
     * Each line is self-contained and intentionally redundant: host, interface,
     * direction, minute bucket, and optional identity fields are all repeated so
     * the file can be tailed, rotated, re-uploaded, or imported independently.
     */
    fputc('{', fp);
    fputs("\"record_type\":", fp); json_escape(fp, is_final ? "final" : "update"); fputc(',', fp);
    fputs("\"host\":", fp); json_escape(fp, host ? host : "unknown"); fputc(',', fp);
    fputs("\"iface\":", fp); json_escape(fp, iface ? iface : "unknown"); fputc(',', fp);
    fprintf(fp, "\"minute_ts\":%llu,", (unsigned long long)entry->minute_bucket);
    fputs("\"minute_iso\":", fp); json_escape(fp, minute_iso); fputc(',', fp);
    fputs("\"first_seen_iso\":", fp); json_escape(fp, first_seen_iso); fputc(',', fp);
    fputs("\"last_seen_iso\":", fp); json_escape(fp, last_seen_iso); fputc(',', fp);
    fprintf(fp, "\"proto\":%u,", (unsigned)entry->key.proto);
    fputs("\"class\":", fp); json_escape(fp, entry->class_tag[0] ? entry->class_tag : "other"); fputc(',', fp);
    fputs("\"direction\":", fp); json_escape(fp, flow_direction_str(entry->direction)); fputc(',', fp);
    if (include_identity_fields) {
        fprintf(fp, "\"pid\":%d,", entry->pid);
        fputs("\"attr_source\":", fp); json_escape(fp, attr_source_str(entry->attr_source)); fputc(',', fp);
        fputs("\"process\":", fp); json_escape(fp, entry->process[0] ? entry->process : "unknown"); fputc(',', fp);
        fputs("\"cmdline\":", fp); json_escape(fp, entry->cmdline[0] ? entry->cmdline : ""); fputc(',', fp);
    }
    fputs("\"workload\":", fp); json_escape(fp, entry->workload[0] ? entry->workload : ""); fputc(',', fp);
    if (entry->sni[0]) {
        fputs("\"sni\":", fp); json_escape(fp, entry->sni); fputc(',', fp);
    }
    if (entry->host[0]) {
        fputs("\"host_name\":", fp); json_escape(fp, entry->host); fputc(',', fp);
    }
    fputs("\"src_ip\":", fp); json_escape(fp, entry->key.src_ip); fputc(',', fp);
    fprintf(fp, "\"src_port\":%u,", (unsigned)entry->key.src_port);
    fputs("\"dst_ip\":", fp); json_escape(fp, entry->key.dst_ip); fputc(',', fp);
    fprintf(fp, "\"dst_port\":%u,", (unsigned)entry->key.dst_port);
    fprintf(fp, "\"packets\":%llu,", (unsigned long long)entry->packets);
    fprintf(fp, "\"bytes\":%llu,", (unsigned long long)entry->bytes);
    fputs("\"bytes_human\":", fp); json_escape(fp, bytes_human); fputc(',', fp);
    fprintf(fp, "\"connections\":%llu,", (unsigned long long)entry->connections);
    fprintf(fp, "\"connections_effective\":%llu,", (unsigned long long)flow_connections_effective(entry, is_final));
    fputs("\"connection_inferred\":", fp); fputs(flow_connection_inferred(entry) ? "true" : "false", fp); fputc(',', fp);
    fputs("\"tcp_seen_without_syn\":", fp); fputs(flow_tcp_seen_without_syn(entry, is_final) ? "true" : "false", fp);
    fputs("}\n", fp);
    fflush(fp);
}
