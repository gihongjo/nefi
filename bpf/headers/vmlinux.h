// vmlinux.h — Minimal kernel type definitions for eBPF programs.
// In production, generate the full vmlinux.h with:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// This file provides only the types needed by nefi eBPF programs.

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef int bool;
#define true 1
#define false 0

// Network byte-order types required by bpf_helper_defs.h.
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u32 __wsum;

// BPF map types.
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_RINGBUF = 27,
};

// BPF map update flags.
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

// BPF perf event output flags.
#define BPF_F_CURRENT_CPU 0xFFFFFFFFULL

// pt_regs for kprobes (x86_64).
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
} __attribute__((preserve_access_index));

// Minimal socket structures needed for tracepoints.
struct sock_common {
    union {
        struct {
            __u32 skc_daddr;
            __u32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __u16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
    volatile unsigned char skc_state;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct inet_sock {
    struct sock sk;
} __attribute__((preserve_access_index));

// For tcp_sendmsg / tcp_recvmsg kprobes.
struct msghdr {
    void *msg_name;
    int msg_namelen;
    // Remaining fields omitted for simplicity.
} __attribute__((preserve_access_index));

struct iov_iter {
    // Simplified — full definition from vmlinux.h needed in production.
    unsigned long count;
} __attribute__((preserve_access_index));

// Tracepoint context for inet_sock_set_state.
struct trace_event_raw_inet_sock_set_state {
    // Common tracepoint fields.
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
