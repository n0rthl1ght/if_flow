#ifndef IF_FLOW_SHARED_H
#define IF_FLOW_SHARED_H

#include <stdint.h>

#define TASK_COMM_LEN 16
#define EVENT_SRC_CONNECT 1
#define EVENT_SRC_DATAPATH 2

struct tuple_v4 {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
    uint8_t pad1;
    uint16_t pad2;
};

struct ebpf_event_v4 {
    uint64_t ts_ns;
    uint32_t pid;
    uint8_t source;
    uint8_t pad0;
    uint16_t pad1;
    struct tuple_v4 t;
    char comm[TASK_COMM_LEN];
};

#endif
