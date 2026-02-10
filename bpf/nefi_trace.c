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

#define MAX_MSG_SIZE 512

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

// ─── Data structures ────────────────────────────────────────────

struct data_event_t {
	u64  timestamp_ns;
	u32  pid;
	u32  fd;
	u32  msg_size;
	u8   direction; // 0 = send, 1 = recv
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
	__uint(max_entries, 1024 * 1024); // 1 MB
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
	// Bitmask ensures verifier can prove bound (MAX_MSG_SIZE is 512 = power of 2)
	copy &= (MAX_MSG_SIZE - 1);
	bpf_probe_read_user(&event->msg, copy + 1, (void *)a->buf);

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
