// SPDX-License-Identifier: GPL-2.0
//
// nefi_trace.c — libbpf/CO-RE socket data capture
// Traces socket I/O via syscall tracepoints and captures payload.
// Ported from the working BCC test (test_socket_trace.py).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

#define MAX_MSG_SIZE 4096

// ─── Tracepoint context structs ─────────────────────────────────
// These match the kernel tracepoint format (common header included).

struct trace_event_raw_sys_enter {
	unsigned short common_type;
	unsigned char  common_flags;
	unsigned char  common_preempt_count;
	int            common_pid;
	long           id;
	unsigned long  args[6];
};

struct trace_event_raw_sys_exit {
	unsigned short common_type;
	unsigned char  common_flags;
	unsigned char  common_preempt_count;
	int            common_pid;
	long           id;
	long           ret;
};

// ─── Protocol enum (matches Pixie traffic_protocol_t) ───────────

enum protocol_t {
	PROTO_UNKNOWN = 0,
	PROTO_HTTP    = 1,
	PROTO_HTTP2   = 2,
	PROTO_MYSQL   = 3,
	PROTO_CQL     = 4,
	PROTO_PGSQL   = 5,
	PROTO_DNS     = 6,
	PROTO_REDIS   = 7,
	PROTO_NATS    = 8,
	PROTO_MONGO   = 9,
	PROTO_KAFKA   = 10,
	PROTO_MUX     = 11,
	PROTO_AMQP    = 12,
	PROTO_TLS     = 13,
};

// ─── Data structures ────────────────────────────────────────────

struct data_event_t {
	u64  timestamp_ns;
	u32  pid;
	u32  fd;
	u32  msg_size;
	u8   direction; // 0 = send, 1 = recv
	u8   protocol;
	char comm[16];
	char msg[MAX_MSG_SIZE];
} __attribute__((packed));

struct args_t {
	u64 buf; // userspace buffer pointer
	u32 fd;
};

// ─── BPF Maps ───────────────────────────────────────────────────

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4 MB
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);  // pid<<32 | fd
	__type(value, u8);
} socket_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64); // pid_tgid
	__type(value, struct args_t);
} active_send_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct args_t);
} active_recv_args SEC(".maps");

// ─── Protocol detection ─────────────────────────────────────────
// Inspects first bytes of captured payload. Best-effort; Go can
// refine further. Ordered: text protocols first (high confidence),
// then binary protocols (heuristic).

static __always_inline u8 detect_protocol(const char *msg, u32 len)
{
	if (len < 4)
		return PROTO_UNKNOWN;

	u8 b0 = (u8)msg[0];
	u8 b1 = (u8)msg[1];
	u8 b2 = (u8)msg[2];
	u8 b3 = (u8)msg[3];

	// ── TLS: 0x16 (handshake) + version 0x03.{01-04} ──
	if (b0 == 0x16 && b1 == 0x03 && b2 >= 0x01 && b2 <= 0x04)
		return PROTO_TLS;

	// ── AMQP: "AMQP" magic ──
	if (b0 == 'A' && b1 == 'M' && b2 == 'Q' && b3 == 'P')
		return PROTO_AMQP;

	// ── Text-based: first-byte switch (HTTP, NATS, Redis) ──
	switch (b0) {
	case 'G':
		if (b1 == 'E' && b2 == 'T' && b3 == ' ')
			return PROTO_HTTP;
		break;
	case 'P':
		if (b1 == 'R' && b2 == 'I' && b3 == ' ')
			return PROTO_HTTP2;
		if (len >= 5 && b1 == 'O' && b2 == 'S' && b3 == 'T' &&
		    (u8)msg[4] == ' ')
			return PROTO_HTTP;
		if (b1 == 'U' && b2 == 'T' && b3 == ' ')
			return PROTO_HTTP;
		if (len >= 6 && b1 == 'A' && b2 == 'T' && b3 == 'C' &&
		    (u8)msg[4] == 'H' && (u8)msg[5] == ' ')
			return PROTO_HTTP;
		// NATS
		if (b1 == 'U' && b2 == 'B' && b3 == ' ')
			return PROTO_NATS;
		if (b1 == 'I' && b2 == 'N' && b3 == 'G')
			return PROTO_NATS;
		if (b1 == 'O' && b2 == 'N' && b3 == 'G')
			return PROTO_NATS;
		break;
	case 'H':
		if (len >= 6 && b1 == 'T' && b2 == 'T' && b3 == 'P' &&
		    (u8)msg[4] == '/') {
			if ((u8)msg[5] == '2')
				return PROTO_HTTP2;
			return PROTO_HTTP;
		}
		if (len >= 5 && b1 == 'E' && b2 == 'A' && b3 == 'D' &&
		    (u8)msg[4] == ' ')
			return PROTO_HTTP;
		break;
	case 'D':
		if (len >= 7 && b1 == 'E' && b2 == 'L' && b3 == 'E' &&
		    (u8)msg[4] == 'T' && (u8)msg[5] == 'E' && (u8)msg[6] == ' ')
			return PROTO_HTTP;
		break;
	case 'O':
		if (len >= 8 && b1 == 'P' && b2 == 'T' && b3 == 'I' &&
		    (u8)msg[4] == 'O' && (u8)msg[5] == 'N' && (u8)msg[6] == 'S' &&
		    (u8)msg[7] == ' ')
			return PROTO_HTTP;
		break;
	case 'C':
		if (len >= 8 && b1 == 'O' && b2 == 'N' && b3 == 'N' &&
		    (u8)msg[4] == 'E' && (u8)msg[5] == 'C' && (u8)msg[6] == 'T' &&
		    (u8)msg[7] == ' ')
			return PROTO_HTTP;
		break;
	// NATS text commands
	case 'I':
		if (len >= 5 && b1 == 'N' && b2 == 'F' && b3 == 'O' &&
		    (u8)msg[4] == ' ')
			return PROTO_NATS;
		break;
	case 'M':
		if (b1 == 'S' && b2 == 'G' && b3 == ' ')
			return PROTO_NATS;
		break;
	case 'S':
		if (b1 == 'U' && b2 == 'B' && b3 == ' ')
			return PROTO_NATS;
		break;
	// Redis RESP / NATS ack
	case '+':
		if (b1 == 'O' && b2 == 'K')
			return PROTO_NATS;
		if (b1 >= '0' && b1 <= '9')
			return PROTO_REDIS;
		break;
	case '-':
		if (b1 == 'E' && b2 == 'R' && b3 == 'R')
			return PROTO_NATS;
		if (b1 >= '0' && b1 <= '9')
			return PROTO_REDIS;
		break;
	case '*':
	case '$':
	case ':':
		if (b1 >= '0' && b1 <= '9')
			return PROTO_REDIS;
		break;
	}

	// ── MySQL: 3-byte len + seq=0 + known command byte ──
	if (len >= 5 && b3 == 0) {
		u8 cmd = (u8)msg[4];
		if (cmd == 0x0a || // server greeting (v10)
		    cmd == 0x01 || // COM_QUIT
		    cmd == 0x02 || // COM_INIT_DB
		    cmd == 0x03 || // COM_QUERY
		    cmd == 0x04 || // COM_FIELD_LIST
		    cmd == 0x16 || // COM_STMT_PREPARE
		    cmd == 0x17 || // COM_STMT_EXECUTE
		    cmd == 0x19)   // COM_STMT_CLOSE
			return PROTO_MYSQL;
	}
	// MySQL response: seq > 0, OK/ERR/EOF marker
	if (len >= 5 && b3 > 0 && b3 < 10) {
		u8 resp = (u8)msg[4];
		if (resp == 0x00 || resp == 0xFE || resp == 0xFF)
			return PROTO_MYSQL;
	}

	// ── CQL (Cassandra): version byte + valid opcode ──
	if (len >= 9 &&
	    (b0 == 0x03 || b0 == 0x04 || b0 == 0x05 ||
	     b0 == 0x83 || b0 == 0x84 || b0 == 0x85)) {
		if ((u8)msg[4] <= 0x10)
			return PROTO_CQL;
	}

	// ── PostgreSQL ──
	// Startup message: 4-byte length + protocol version 3.0
	if (len >= 8) {
		u32 ver = ((u32)(u8)msg[4] << 24) | ((u32)(u8)msg[5] << 16) |
			  ((u32)(u8)msg[6] << 8)  | (u32)(u8)msg[7];
		if (ver == 0x00030000)
			return PROTO_PGSQL;
	}
	// Regular message: type byte + 4-byte big-endian length
	if (len >= 5 &&
	    (b0 == 'Q' || b0 == 'R' || b0 == 'T' || b0 == 'X' ||
	     b0 == 'E' || b0 == 'Z' || b0 == 'K')) {
		u32 plen = ((u32)b1 << 24) | ((u32)b2 << 16) |
			   ((u32)b3 << 8)  | (u32)(u8)msg[4];
		if (plen >= 4 && plen <= 0x100000)
			return PROTO_PGSQL;
	}

	// ── DNS (over TCP): 2-byte length + header ──
	if (len >= 12) {
		u16 dns_len = ((u16)b0 << 8) | b1;
		u8 flags_hi = (u8)msg[4];
		u8 opcode   = (flags_hi >> 3) & 0x0F;
		u16 qdcount = ((u16)(u8)msg[6] << 8) | (u8)msg[7];
		if (dns_len >= 12 && dns_len < 4096 &&
		    opcode <= 2 && qdcount >= 1 && qdcount <= 16)
			return PROTO_DNS;
	}

	// ── MongoDB: 4-byte LE length + reqID + respTo + opcode ──
	if (len >= 16) {
		u32 mlen = (u32)b0 | ((u32)b1 << 8) |
			   ((u32)b2 << 16) | ((u32)b3 << 24);
		u32 opcode = (u32)(u8)msg[12] | ((u32)(u8)msg[13] << 8) |
			     ((u32)(u8)msg[14] << 16) | ((u32)(u8)msg[15] << 24);
		if (mlen >= 16 && mlen <= 0x2000000 &&
		    (opcode == 1 || opcode == 2004 || opcode == 2013))
			return PROTO_MONGO;
	}

	// ── Kafka: 4-byte BE length + 2-byte API key + 2-byte version ──
	if (len >= 8) {
		u32 klen = ((u32)b0 << 24) | ((u32)b1 << 16) |
			   ((u32)b2 << 8) | (u32)b3;
		u16 api_key = ((u16)(u8)msg[4] << 8) | (u8)msg[5];
		u16 api_ver = ((u16)(u8)msg[6] << 8) | (u8)msg[7];
		if (klen >= 4 && klen <= 0x6400000 &&
		    api_key <= 67 && api_ver <= 15)
			return PROTO_KAFKA;
	}

	return PROTO_UNKNOWN;
}

// ─── Emit helper ────────────────────────────────────────────────

static __always_inline int emit_event(struct args_t *a, long bytes, u8 direction)
{
	struct data_event_t *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = id >> 32;
	event->fd = a->fd;
	event->direction = direction;
	event->msg_size = (u32)bytes;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Clamp read size for verifier
	u32 copy = (u32)bytes;
	if (copy > MAX_MSG_SIZE)
		copy = MAX_MSG_SIZE;
	// Bitmask ensures verifier can prove bound (MAX_MSG_SIZE is power of 2)
	copy &= (MAX_MSG_SIZE - 1);
	bpf_probe_read_user(&event->msg, copy + 1, (void *)a->buf);

	event->protocol = detect_protocol(event->msg, copy);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

// ─── Track socket FDs via connect / accept ──────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	u64 key = ((u64)pid << 32) | (u32)fd;
	u8 val  = 1;
	bpf_map_update_elem(&socket_fds, &key, &val, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tp_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
	long fd = ctx->ret;
	if (fd < 0)
		return 0;

	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	u64 key = ((u64)pid << 32) | (u32)fd;
	u8 val  = 1;
	bpf_map_update_elem(&socket_fds, &key, &val, BPF_ANY);
	return 0;
}

// ─── write (socket only) ────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	if (fd <= 2)
		return 0;

	u64 sock_key = ((u64)pid << 32) | (u32)fd;
	if (!bpf_map_lookup_elem(&socket_fds, &sock_key))
		return 0;

	struct args_t a = {};
	a.buf = ctx->args[1];
	a.fd  = (u32)fd;
	bpf_map_update_elem(&active_send_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct args_t *a = bpf_map_lookup_elem(&active_send_args, &id);
	if (!a)
		return 0;

	long ret = ctx->ret;
	if (ret > 0)
		emit_event(a, ret, 0);

	bpf_map_delete_elem(&active_send_args, &id);
	return 0;
}

// ─── read (socket only) ─────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	if (fd <= 2)
		return 0;

	u64 sock_key = ((u64)pid << 32) | (u32)fd;
	if (!bpf_map_lookup_elem(&socket_fds, &sock_key))
		return 0;

	struct args_t a = {};
	a.buf = ctx->args[1];
	a.fd  = (u32)fd;
	bpf_map_update_elem(&active_recv_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct args_t *a = bpf_map_lookup_elem(&active_recv_args, &id);
	if (!a)
		return 0;

	long ret = ctx->ret;
	if (ret > 0)
		emit_event(a, ret, 1);

	bpf_map_delete_elem(&active_recv_args, &id);
	return 0;
}

// ─── sendto ─────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	// sendto is always on a socket — auto-mark
	u64 sock_key = ((u64)pid << 32) | (u32)fd;
	u8 val = 1;
	bpf_map_update_elem(&socket_fds, &sock_key, &val, BPF_ANY);

	struct args_t a = {};
	a.buf = ctx->args[1];
	a.fd  = (u32)fd;
	bpf_map_update_elem(&active_send_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tp_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct args_t *a = bpf_map_lookup_elem(&active_send_args, &id);
	if (!a)
		return 0;

	long ret = ctx->ret;
	if (ret > 0)
		emit_event(a, ret, 0);

	bpf_map_delete_elem(&active_send_args, &id);
	return 0;
}

// ─── recvfrom ───────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	// recvfrom is always on a socket — auto-mark
	u64 sock_key = ((u64)pid << 32) | (u32)fd;
	u8 val = 1;
	bpf_map_update_elem(&socket_fds, &sock_key, &val, BPF_ANY);

	struct args_t a = {};
	a.buf = ctx->args[1];
	a.fd  = (u32)fd;
	bpf_map_update_elem(&active_recv_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct args_t *a = bpf_map_lookup_elem(&active_recv_args, &id);
	if (!a)
		return 0;

	long ret = ctx->ret;
	if (ret > 0)
		emit_event(a, ret, 1);

	bpf_map_delete_elem(&active_recv_args, &id);
	return 0;
}

// ─── close (cleanup socket_fds) ─────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_close")
int tp_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	u64 key = ((u64)pid << 32) | (u32)fd;
	bpf_map_delete_elem(&socket_fds, &key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
