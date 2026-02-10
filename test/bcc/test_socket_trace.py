#!/usr/bin/env python3
"""
BCC test: trace network I/O via tracepoints and capture payload.
Only traces socket-related syscalls (sendto/recvfrom/sendmsg/recvmsg)
and filters out system noise.

Usage: sudo python3 test_socket_trace.py
Then:  curl http://example.com   (in another terminal)
"""

import ctypes
import signal
import sys
import os

from bcc import BPF

# Get our own PID to filter out self-tracing feedback loop
SELF_PID = os.getpid()

BPF_SRC = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_MSG_SIZE 512
#define SELF_PID __SELF_PID__

struct data_event_t {
    u64  timestamp_ns;
    u32  pid;
    u32  fd;
    u32  msg_size;
    u8   direction;  // 0=send, 1=recv
    char comm[16];
    char msg[MAX_MSG_SIZE];
};

BPF_PERF_OUTPUT(data_events);
BPF_PERCPU_ARRAY(event_buffer, struct data_event_t, 1);

// Track socket fds: hook connect() and accept() entry
// Key: tgid<<32 | fd, Value: 1 (is socket)
BPF_HASH(socket_fds, u64, u8, 65536);

struct args_t {
    const char *buf;
    int fd;
};
BPF_HASH(active_send_args, u64, struct args_t);
BPF_HASH(active_recv_args, u64, struct args_t);

// ─── Track socket fds via connect/accept ──────────────────────────

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    long ret = args->ret;
    // connect returns 0 on success or -EINPROGRESS for non-blocking
    if (ret != 0 && ret != -115) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    // We need the fd from entry — for simplicity, mark all recent fds
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    int fd = args->fd;
    u64 key = ((u64)pid << 32) | (u32)fd;
    u8 val = 1;
    socket_fds.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    long fd = args->ret;
    if (fd < 0) return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    u64 key = ((u64)pid << 32) | (u32)fd;
    u8 val = 1;
    socket_fds.update(&key, &val);
    return 0;
}

// ─── Emit helper ──────────────────────────────────────────────────

static __always_inline int emit_event(void *ctx, struct args_t *a,
                                       long bytes, u8 direction) {
    int zero = 0;
    struct data_event_t *event = event_buffer.lookup(&zero);
    if (event == NULL) return 0;

    u64 id = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->fd = a->fd;
    event->direction = direction;
    event->msg_size = bytes;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    u32 copy = bytes < MAX_MSG_SIZE ? bytes : MAX_MSG_SIZE;
    bpf_probe_read_user(&event->msg, copy, a->buf);

    data_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// ─── write (socket only) ──────────────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    int fd = args->fd;
    if (fd <= 2) return 0;

    // Only trace known socket fds
    u64 key = ((u64)pid << 32) | (u32)fd;
    if (socket_fds.lookup(&key) == NULL) return 0;

    struct args_t a = {};
    a.buf = (const char *)args->buf;
    a.fd = fd;
    active_send_args.update(&id, &a);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 id = bpf_get_current_pid_tgid();
    struct args_t *a = active_send_args.lookup(&id);
    if (a == NULL) return 0;

    long ret = args->ret;
    if (ret > 0) emit_event(args, a, ret, 0);

    active_send_args.delete(&id);
    return 0;
}

// ─── read (socket only) ───────────────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    int fd = args->fd;
    if (fd <= 2) return 0;

    u64 key = ((u64)pid << 32) | (u32)fd;
    if (socket_fds.lookup(&key) == NULL) return 0;

    struct args_t a = {};
    a.buf = (const char *)args->buf;
    a.fd = fd;
    active_recv_args.update(&id, &a);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 id = bpf_get_current_pid_tgid();
    struct args_t *a = active_recv_args.lookup(&id);
    if (a == NULL) return 0;

    long ret = args->ret;
    if (ret > 0) emit_event(args, a, ret, 1);

    active_recv_args.delete(&id);
    return 0;
}

// ─── sendto ───────────────────────────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    int fd = args->fd;
    // sendto is always on a socket — mark it
    u64 key = ((u64)pid << 32) | (u32)fd;
    u8 val = 1;
    socket_fds.update(&key, &val);

    struct args_t a = {};
    a.buf = (const char *)args->buff;
    a.fd = fd;
    active_send_args.update(&id, &a);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    u64 id = bpf_get_current_pid_tgid();
    struct args_t *a = active_send_args.lookup(&id);
    if (a == NULL) return 0;

    long ret = args->ret;
    if (ret > 0) emit_event(args, a, ret, 0);

    active_send_args.delete(&id);
    return 0;
}

// ─── recvfrom ─────────────────────────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid == SELF_PID) return 0;

    int fd = args->fd;
    u64 key = ((u64)pid << 32) | (u32)fd;
    u8 val = 1;
    socket_fds.update(&key, &val);

    struct args_t a = {};
    a.buf = (const char *)args->ubuf;
    a.fd = fd;
    active_recv_args.update(&id, &a);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u64 id = bpf_get_current_pid_tgid();
    struct args_t *a = active_recv_args.lookup(&id);
    if (a == NULL) return 0;

    long ret = args->ret;
    if (ret > 0) emit_event(args, a, ret, 1);

    active_recv_args.delete(&id);
    return 0;
}

// ─── Clean up on close ────────────────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int fd = args->fd;
    u64 key = ((u64)pid << 32) | (u32)fd;
    socket_fds.delete(&key);
    return 0;
}
""".replace("__SELF_PID__", str(SELF_PID))


class DataEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("fd", ctypes.c_uint32),
        ("msg_size", ctypes.c_uint32),
        ("direction", ctypes.c_uint8),
        ("comm", ctypes.c_char * 16),
        ("msg", ctypes.c_char * 512),
    ]


def main():
    print("=" * 60)
    print("  Nefi BCC Socket Data Capture Test v3")
    print("  (socket-only, filtered)")
    print("=" * 60)

    b = BPF(text=BPF_SRC)
    print("[+] BPF compiled & tracepoints attached!")
    print(f"[*] Filtering out self PID={SELF_PID}")

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(DataEvent)).contents
        d = "SEND >>>" if event.direction == 0 else "RECV <<<"
        comm = event.comm.decode("utf-8", errors="replace").rstrip("\x00")

        # Show payload (printable ASCII)
        raw = event.msg[:min(event.msg_size, 200)]
        payload = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)

        print(f"  {d} | pid={event.pid:<6} fd={event.fd:<4} "
              f"size={event.msg_size:<6} [{comm}]")
        if payload.strip("."):
            print(f"           | {payload[:120]}")
            if len(payload) > 120:
                print(f"           | {payload[120:240]}")

    b["data_events"].open_perf_buffer(handle_event, page_cnt=256)

    print("[*] Tracing socket I/O... Press Ctrl+C to stop.")
    print("[*] Generate traffic: curl http://example.com\n")

    running = True
    def sig_handler(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, sig_handler)

    while running:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
