// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define EVENT_SRC_CONNECT 1
#define EVENT_SRC_DATAPATH 2

struct tuple_v4 {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad1;
    __u16 pad2;
};

struct ebpf_event_v4 {
    __u64 ts_ns;
    __u32 pid;
    __u8 source;
    __u8 pad0;
    __u16 pad1;
    struct tuple_v4 t;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline int submit_from_sock(struct sock *sk, __u8 source) {
    struct ebpf_event_v4 *e;
    struct sock_common sc;
    struct inet_sock *isk = (struct inet_sock *)sk;
    __u16 proto = 0;
    __u32 saddr = 0;
    __u32 daddr = 0;
    __u16 sport_be = 0;
    __u16 dport_be = 0;

    if (!sk) return 0;

    bpf_core_read(&sc, sizeof(sc), &sk->__sk_common);
    if (sc.skc_dport == 0) return 0;

    bpf_core_read(&proto, sizeof(proto), &sk->sk_protocol);
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return 0;

    bpf_core_read(&saddr, sizeof(saddr), &isk->inet_saddr);
    daddr = sc.skc_daddr;
    bpf_core_read(&sport_be, sizeof(sport_be), &isk->inet_sport);
    dport_be = sc.skc_dport;

    if (daddr == 0 || dport_be == 0) return 0;
    if (sport_be == 0 && sc.skc_num != 0) sport_be = bpf_htons(sc.skc_num);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->source = source;
    e->t.saddr = saddr;
    e->t.daddr = daddr;
    e->t.sport = bpf_ntohs(sport_be);
    e->t.dport = bpf_ntohs(dport_be);
    e->t.proto = proto;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kp_tcp_connect, struct sock *sk) {
    return submit_from_sock(sk, EVENT_SRC_CONNECT);
}

SEC("kprobe/ip_local_out")
int BPF_KPROBE(kp_ip_local_out, struct net *net, struct sock *sk, struct sk_buff *skb) {
    (void)net;
    (void)skb;
    return submit_from_sock(sk, EVENT_SRC_DATAPATH);
}

SEC("kprobe/ip_rcv")
int BPF_KPROBE(kp_ip_rcv, struct sk_buff *skb) {
    struct sock *sk = NULL;
    if (!skb) return 0;
    bpf_core_read(&sk, sizeof(sk), &skb->sk);
    return submit_from_sock(sk, EVENT_SRC_DATAPATH);
}
