// http_parser.c — eBPF program for L7 HTTP request/response parsing.
//
// Hooks:
//   kprobe/tcp_sendmsg   — Capture outgoing HTTP requests (method + path)
//   kretprobe/tcp_recvmsg — Capture HTTP response status codes
//
// Parses the first bytes of TCP payload to detect HTTP/1.x patterns.

#include "headers/common.h"

// Map to correlate requests with responses for latency measurement.
// key: conn_key, value: request start timestamp.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, __u64);
} http_req_start SEC(".maps");

// Perf buffer for HTTP events.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} http_events SEC(".maps");

// Temporary storage for socket info across kprobe/kretprobe.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // pid_tgid
    __type(value, struct conn_key);
} active_recv SEC(".maps");

// HTTP method detection constants.
#define HTTP_GET    0x20544547  // "GET "
#define HTTP_POST   0x54534F50  // "POST"
#define HTTP_PUT    0x20545550  // "PUT "
#define HTTP_DEL    0x454C4544  // "DELE"
#define HTTP_PAT    0x43544150  // "PATC"
#define HTTP_HEA    0x44414548  // "HEAD"
#define HTTP_OPT    0x4954504F  // "OPTI"

// Detect HTTP method from the first 4 bytes of payload.
static __always_inline __u8 detect_method(__u32 first_word) {
    if (first_word == HTTP_GET)  return 1; // GET
    if (first_word == HTTP_POST) return 2; // POST
    if (first_word == HTTP_PUT)  return 3; // PUT
    if (first_word == HTTP_DEL)  return 4; // DELETE
    if (first_word == HTTP_PAT)  return 5; // PATCH
    if (first_word == HTTP_HEA)  return 6; // HEAD
    if (first_word == HTTP_OPT)  return 7; // OPTIONS
    return 0; // Not HTTP
}

// Parse the request path from payload after the method.
// Copies up to 127 bytes of the path into dst.
static __always_inline int parse_path(const char *payload, int offset, char *dst, int max_len) {
    // Find the start of the path (skip method + space).
    int i = offset;
    int j = 0;

    #pragma unroll
    for (; j < 127 && j < max_len; j++) {
        char c;
        bpf_probe_read(&c, 1, payload + i + j);
        if (c == ' ' || c == '?' || c == '\r' || c == '\n' || c == 0)
            break;
        dst[j] = c;
    }
    dst[j] = 0;
    return j;
}

// Parse HTTP response status code: "HTTP/1.x NNN"
static __always_inline __u16 parse_status_code(const char *payload) {
    char buf[16];
    bpf_probe_read(buf, sizeof(buf), payload);

    // Check for "HTTP/1."
    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' || buf[3] != 'P')
        return 0;

    // Status code starts at offset 9: "HTTP/1.1 200"
    __u16 code = 0;
    if (buf[9] >= '0' && buf[9] <= '9')
        code = (buf[9] - '0') * 100;
    if (buf[10] >= '0' && buf[10] <= '9')
        code += (buf[10] - '0') * 10;
    if (buf[11] >= '0' && buf[11] <= '9')
        code += (buf[11] - '0');

    return code;
}

SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    // Read payload from the msghdr.
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg)
        return 0;

    // Read first 4 bytes of payload for method detection.
    // In production, we'd properly walk iov_iter. For now, simplified.
    struct iov_iter *iter;
    bpf_probe_read(&iter, sizeof(iter), (void *)msg + 16); // msg_iter offset
    if (!iter)
        return 0;

    char payload[MAX_PAYLOAD_SIZE];
    long ret = bpf_probe_read(payload, sizeof(payload), (void *)iter);
    if (ret < 0)
        return 0;

    __u32 first_word;
    __builtin_memcpy(&first_word, payload, 4);
    __u8 method = detect_method(first_word);
    if (method == 0)
        return 0; // Not an HTTP request.

    __u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct conn_key key = make_key(src_ip, dst_ip, src_port, dst_port);

    // Record request start time for latency calculation.
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&http_req_start, &key, &ts, BPF_ANY);

    // Emit a partial HTTP event (method + path). Status code will come from response.
    struct http_event event = {};
    event.timestamp_ns = ts;
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.method = method;
    event.status_code = 0; // Unknown until response.
    event.latency_ns = 0;

    // Parse path: skip method length + space.
    int path_offset = 0;
    switch (method) {
        case 1: path_offset = 4; break;  // "GET "
        case 2: path_offset = 5; break;  // "POST "
        case 3: path_offset = 4; break;  // "PUT "
        case 4: path_offset = 7; break;  // "DELETE "
        case 5: path_offset = 6; break;  // "PATCH "
        case 6: path_offset = 5; break;  // "HEAD "
        case 7: path_offset = 8; break;  // "OPTIONS "
    }
    parse_path(payload, path_offset, event.path, 127);

    bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg_enter(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    // Store connection info for the kretprobe.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // For responses, the src/dst are swapped (we're receiving from remote).
    struct conn_key key = make_key(dst_ip, src_ip, dst_port, src_port);
    bpf_map_update_elem(&active_recv, &pid_tgid, &key, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int trace_tcp_recvmsg_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct conn_key *key = bpf_map_lookup_elem(&active_recv, &pid_tgid);
    if (!key)
        return 0;

    struct conn_key k = *key;
    bpf_map_delete_elem(&active_recv, &pid_tgid);

    // Check if there's an outstanding request for this connection.
    __u64 *start_ns = bpf_map_lookup_elem(&http_req_start, &k);
    if (!start_ns)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency = now - *start_ns;

    // Emit response event with latency.
    struct http_event event = {};
    event.timestamp_ns = now;
    event.src_ip = k.src_ip;
    event.dst_ip = k.dst_ip;
    event.src_port = k.src_port;
    event.dst_port = k.dst_port;
    event.method = 0; // Response, not request.
    event.latency_ns = latency;
    // Status code parsing would require reading the received buffer.
    // This is simplified — in production, use a ringbuf or per-CPU array
    // to correlate request/response pairs.
    event.status_code = 0;

    bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));

    bpf_map_delete_elem(&http_req_start, &k);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
