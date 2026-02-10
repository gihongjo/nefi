#ifndef __nefi_COMMON_H__
#define __nefi_COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

#define MAX_PAYLOAD_SIZE 256
#define MAX_CONNECTIONS 65536

// Connection key used to track TCP connections.
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Connection info stored per tracked connection.
struct conn_info {
    __u64 start_ns;
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u32 retransmits;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol; // IPPROTO_TCP=6
};

// Event sent to userspace via perf buffer.
// packed to match exact Go binary parsing offsets.
struct conn_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 duration_ns;
    __u32 retransmits;
    __u8  protocol;
    __u8  _pad[3];
} __attribute__((packed));

// HTTP request event sent to userspace.
struct http_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  method;      // 0=unknown, 1=GET, 2=POST, 3=PUT, 4=DELETE, 5=PATCH, 6=HEAD, 7=OPTIONS
    __u16 status_code;
    __u64 latency_ns;
    char  path[128];
    __u8  _pad[1];
};

// DNS event sent to userspace.
struct dns_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 query_type;
    char  query_name[128];
};

// Helper to construct a connection key.
static __always_inline struct conn_key make_key(__u32 src_ip, __u32 dst_ip,
                                                 __u16 src_port, __u16 dst_port) {
    struct conn_key key = {};
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    return key;
}

#endif /* __nefi_COMMON_H__ */
