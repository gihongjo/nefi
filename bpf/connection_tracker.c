// connection_tracker.c — eBPF program for tracking TCP connection lifecycle.
//
// Hooks:
//   tracepoint/sock/inet_sock_set_state — TCP state transitions (open/close)
//   tracepoint/tcp/tcp_retransmit_skb   — TCP retransmissions
//
// Emits conn_event to userspace via perf buffer on connection close.

#include "headers/common.h"

// Active connections: conn_key → conn_info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} connections SEC(".maps");

// Perf buffer for emitting events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} conn_events SEC(".maps");

// Track retransmissions per connection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, __u32);
} retransmit_count SEC(".maps");

// Tracepoint: sock/inet_sock_set_state
// Fires on every TCP state transition (SYN_SENT→ESTABLISHED, ESTABLISHED→CLOSE, etc.)
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Only handle IPv4 TCP.
    if (ctx->family != AF_INET)
        return 0;

    __u32 src_ip, dst_ip;
    __builtin_memcpy(&src_ip, ctx->saddr, 4);
    __builtin_memcpy(&dst_ip, ctx->daddr, 4);

    __u16 src_port = ctx->sport;
    __u16 dst_port = ctx->dport; // already host byte order from kernel tracepoint

    struct conn_key key = make_key(src_ip, dst_ip, src_port, dst_port);

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    // Connection established — start tracking.
    if (newstate == TCP_ESTABLISHED) {
        struct conn_info info = {};
        info.start_ns = bpf_ktime_get_ns();
        info.bytes_sent = 0;
        info.bytes_recv = 0;
        info.retransmits = 0;
        info.src_ip = src_ip;
        info.dst_ip = dst_ip;
        info.src_port = src_port;
        info.dst_port = dst_port;
        info.protocol = 6; // IPPROTO_TCP

        bpf_map_update_elem(&connections, &key, &info, BPF_ANY);
        return 0;
    }

    // Connection closed — emit event and clean up.
    if (newstate == TCP_CLOSE) {
        struct conn_info *info = bpf_map_lookup_elem(&connections, &key);
        if (!info)
            return 0;

        __u64 now = bpf_ktime_get_ns();

        // Check retransmit counter.
        __u32 retrans = 0;
        __u32 *rcount = bpf_map_lookup_elem(&retransmit_count, &key);
        if (rcount)
            retrans = *rcount;

        struct conn_event event = {};
        event.timestamp_ns = now;
        event.src_ip = info->src_ip;
        event.dst_ip = info->dst_ip;
        event.src_port = info->src_port;
        event.dst_port = info->dst_port;
        event.bytes_sent = info->bytes_sent;
        event.bytes_recv = info->bytes_recv;
        event.duration_ns = now - info->start_ns;
        event.retransmits = retrans;
        event.protocol = info->protocol;

        bpf_perf_event_output(ctx, &conn_events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));

        bpf_map_delete_elem(&connections, &key);
        bpf_map_delete_elem(&retransmit_count, &key);
        return 0;
    }

    return 0;
}

// Tracepoint: tcp/tcp_retransmit_skb
// Fires when a TCP segment is retransmitted.
SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(void *ctx)
{
    struct sock *sk;
    // Read the sock pointer from the tracepoint args.
    // tcp_retransmit_skb tracepoint has skaddr as first field.
    bpf_probe_read(&sk, sizeof(sk), ctx + 8);

    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    __u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct conn_key key = make_key(src_ip, dst_ip, src_port, dst_port);

    __u32 *count = bpf_map_lookup_elem(&retransmit_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u32 init = 1;
        bpf_map_update_elem(&retransmit_count, &key, &init, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
