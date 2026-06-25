#ifndef IF_FLOW_WRITER_JSONL_H
#define IF_FLOW_WRITER_JSONL_H

#include <stdio.h>

#include "flow_table.h"

typedef struct {
    FILE *fp;
    /* User-configured base path, for example /opt/if_flow/if_flow.jsonl. */
    char base_path[1024];
    /* Currently opened file after day-based and size-based rotation are applied. */
    char active_path[1200];
    /* Local day of the active file in YYYY-MM-DD format. */
    char active_day[16];
    /* Zero disables size rotation; otherwise a new suffix is opened when exceeded. */
    size_t max_file_size_bytes;
    /* 0 = plain daily file, 1+ = rotated chunk with -0001, -0002, ... suffix. */
    int active_index;
} jsonl_writer_t;

int jsonl_writer_open(jsonl_writer_t *writer, const char *path, size_t max_file_size_bytes);
void jsonl_writer_close(jsonl_writer_t *writer);
void jsonl_writer_write_flow(jsonl_writer_t *writer, const char *host, const char *iface,
                             const flow_entry_t *entry, int is_final, int include_identity_fields);

#endif
