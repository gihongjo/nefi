// dns_tracker.c — eBPF program for tracking DNS queries (UDP port 53).
//
// Hook: kprobe/udp_sendmsg
//
// Captures DNS query names and types for service discovery correlation.

#include "headers/common.h"

// Perf buffer for DNS events.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} dns_events SEC(".maps");

#define DNS_PORT 53
#define DNS_HEADER_SIZE 12

// Parse DNS query name from wire format (length-prefixed labels).
// Converts "3www6google3com0" → "www.google.com"
static __always_inline int parse_dns_name(const char *payload, int offset, char *dst, int max_len) {
    int i = offset;
    int j = 0;

    #pragma unroll
    for (int labels = 0; labels < 16; labels++) {
        __u8 label_len;
        bpf_probe_read(&label_len, 1, payload + i);
        if (label_len == 0 || label_len > 63)
            break;

        if (j > 0 && j < max_len - 1) {
            dst[j++] = '.';
        }

        i++;
        #pragma unroll
        for (int k = 0; k < 63 && k < label_len; k++) {
            if (j >= max_len - 1)
                break;
            bpf_probe_read(&dst[j], 1, payload + i + k);
            j++;
        }
        i += label_len;
    }
    if (j < max_len)
        dst[j] = 0;
    return j;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    // Only capture DNS traffic (destination port 53).
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (dst_port != DNS_PORT)
        return 0;

    __u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);

    // Read DNS payload (skip UDP header, which is already handled by the kernel).
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg)
        return 0;

    char payload[256];
    struct iov_iter *iter;
    bpf_probe_read(&iter, sizeof(iter), (void *)msg + 16);
    if (!iter)
        return 0;

    long ret = bpf_probe_read(payload, sizeof(payload), (void *)iter);
    if (ret < 0)
        return 0;

    // DNS header: 12 bytes, then question section.
    // Read query type (2 bytes after the name).
    struct dns_event event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.src_port = src_port;

    int name_len = parse_dns_name(payload, DNS_HEADER_SIZE, event.query_name, 127);
    if (name_len <= 0)
        return 0;

    // Query type is 2 bytes after the name null terminator.
    int qtype_offset = DNS_HEADER_SIZE + name_len + 2; // +1 for null, +1 for label length
    __u16 qtype = 0;
    bpf_probe_read(&qtype, 2, payload + qtype_offset);
    event.query_type = bpf_ntohs(qtype);

    bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
