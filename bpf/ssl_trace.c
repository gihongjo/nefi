// SPDX-License-Identifier: GPL-2.0
//
// ssl_trace.c — libbpf/CO-RE SSL/TLS uprobe
// Captures plaintext before encryption (SSL_write, go_tls_write)
// and after decryption (SSL_read, go_tls_read).
//
// The `events` ring buffer is replaced at load time by the shared map
// from nefi_trace via cilium/ebpf MapReplacements so all events flow
// into the same reader loop in main.go.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;

// bpf_helper_defs.h only forward-declares struct pt_regs / user_pt_regs.
// Provide the full definitions per target arch so PT_REGS_* macros work
// without vmlinux.h. Do NOT include linux/ptrace.h — on an arm64 build
// host it would define the arm64 struct pt_regs, clobbering the x86 layout.
#if defined(__TARGET_ARCH_x86)
// libbpf bpf_tracing.h x86 macros reference short field names
// (ax, bx, si, di …) — match that layout here.
struct pt_regs {
	long r15, r14, r13, r12, rbp, rbx;
	long r11, r10, r9, r8;
	long rax, rcx, rdx, rsi, rdi, orig_rax;
	long rip, cs, eflags, rsp, ss;
};
#else
// arm64: bpf_tracing.h casts pt_regs → struct user_pt_regs
struct user_pt_regs {
	u64 regs[31];
	u64 sp;
	u64 pc;
	u64 pstate;
};
#endif

#define MAX_MSG_SIZE 4096

// Protocol / message-type constants — must match nefi_trace.c and model/events.go
#define PROTO_TLS    13
#define MSG_UNKNOWN  0
#define MSG_REQUEST  1
#define MSG_RESPONSE 2

// ─── data_event_t: exact same packed layout as nefi_trace.c ─────
// Total size: 8+4+4+4+1+1+1+16+4096 = 4135 bytes

struct data_event_t {
	u64  timestamp_ns;
	u32  pid;
	u32  fd;       // 0 for uprobe-captured events (FD unknown)
	u32  msg_size;
	u8   direction; // 0 = send, 1 = recv
	u8   protocol;
	u8   msg_type;  // 0 = unknown, 1 = request, 2 = response
	char comm[16];
	char msg[MAX_MSG_SIZE];
} __attribute__((packed));

// ─── Saved-argument struct ───────────────────────────────────────

struct ssl_buf_args_t {
	u64 buf; // userspace buffer pointer saved at uprobe entry
};

// ─── BPF Maps ───────────────────────────────────────────────────

// events: replaced at load time with nefi_trace's ring buffer
// (cilium/ebpf CollectionOptions.MapReplacements{"events": sharedMap})
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4 MB placeholder
} events SEC(".maps");

// OpenSSL: buf pointer saved between SSL_write entry and ret
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);  // pid_tgid
	__type(value, struct ssl_buf_args_t);
} active_ssl_write_args SEC(".maps");

// OpenSSL: buf pointer saved between SSL_read entry and ret
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct ssl_buf_args_t);
} active_ssl_read_args SEC(".maps");

// Go TLS: slice data pointer saved between Read entry and ret uprobe.
// Write does not need a map — the full buffer is available at entry.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct ssl_buf_args_t);
} active_go_tls_read_args SEC(".maps");

// ─── Go register-ABI macros ──────────────────────────────────────
//
// Go amd64 ABI (register-based, Go 1.17+):
//   integer/pointer args: AX, BX, CX, DI, SI, R8, R9, R10, R11
//   integer/pointer rets: AX, BX, CX
//
// Go arm64 ABI:
//   same integer arg registers as C ABI: R0-R8
//   → PT_REGS_PARM1/2/3 and PT_REGS_RC work directly
//
// For crypto/tls.(*Conn).Write(b []byte) (int, error):
//   arg0 = receiver *Conn
//   arg1 = b.data  (slice pointer we want)
//   arg2 = b.len
//   ret0 = n (bytes written/read)
//   ret1 = error.type
//   ret2 = error.value

#if defined(__TARGET_ARCH_x86)
  // amd64: Go ABI uses AX/BX/CX/DI for first 4 integer args
  #define GO_ARG1(ctx)  ((ctx)->rbx)  // b.data (2nd arg after receiver)
  #define GO_ARG2(ctx)  ((ctx)->rcx)  // b.len  (3rd arg)
  #define GO_RC0(ctx)   ((ctx)->rax)  // return n
#else
  // arm64 (and others): Go ABI coincides with C ABI for these positions
  #define GO_ARG1(ctx)  PT_REGS_PARM2(ctx)  // b.data
  #define GO_ARG2(ctx)  PT_REGS_PARM3(ctx)  // b.len
  #define GO_RC0(ctx)   PT_REGS_RC(ctx)     // return n
#endif

// ─── Emit helper ─────────────────────────────────────────────────

static __always_inline int emit_ssl_event(u64 buf_addr, long bytes, u8 direction)
{
	if (bytes <= 0)
		return 0;

	struct data_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid          = pid;
	event->fd           = 0;  // FD not available in uprobe context
	event->direction    = direction;
	event->msg_size     = (u32)bytes;
	event->protocol     = PROTO_TLS;
	// direction=0 (send) → request; direction=1 (recv) → response
	event->msg_type     = (direction == 0) ? MSG_REQUEST : MSG_RESPONSE;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	u32 copy = (u32)bytes;
	if (copy > MAX_MSG_SIZE)
		copy = MAX_MSG_SIZE;
	copy &= (MAX_MSG_SIZE - 1); // verifier: prove copy < MAX_MSG_SIZE
	bpf_probe_read_user(&event->msg, copy + 1, (void *)buf_addr);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

// ─── OpenSSL: SSL_write ──────────────────────────────────────────
// Signature: int SSL_write(SSL *ssl, const void *buf, int num)
//   PARM1 = ssl (ignored)
//   PARM2 = buf (plaintext to encrypt)
//   PARM3 = num
//   RC    = bytes written (on ret)

SEC("uprobe/SSL_write")
int uprobe_ssl_write_entry(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_buf_args_t a = {};
	a.buf = PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&active_ssl_write_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_buf_args_t *a = bpf_map_lookup_elem(&active_ssl_write_args, &id);
	if (a)
		emit_ssl_event(a->buf, PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&active_ssl_write_args, &id);
	return 0;
}

// ─── OpenSSL: SSL_read ───────────────────────────────────────────
// Signature: int SSL_read(SSL *s, void *buf, int num)
//   PARM1 = ssl (ignored)
//   PARM2 = buf (decrypted data destination)
//   RC    = bytes read (on ret)

SEC("uprobe/SSL_read")
int uprobe_ssl_read_entry(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_buf_args_t a = {};
	a.buf = PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&active_ssl_read_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_buf_args_t *a = bpf_map_lookup_elem(&active_ssl_read_args, &id);
	if (a)
		emit_ssl_event(a->buf, PT_REGS_RC(ctx), 1);
	bpf_map_delete_elem(&active_ssl_read_args, &id);
	return 0;
}

// ─── Go TLS: crypto/tls.(*Conn).Write ───────────────────────────
// Signature (Go register ABI): func (c *Conn) Write(b []byte) (int, error)
//   GO_ARG1 = b.data (slice data pointer — the plaintext bytes)
//   GO_ARG2 = b.len
//
// Write의 경우 plaintext 버퍼와 길이가 entry 시점에 이미 레지스터에 있으므로
// uretprobe 없이 entry probe에서 즉시 emit한다.

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write_entry(struct pt_regs *ctx)
{
	u64 buf = GO_ARG1(ctx);
	long len = (long)GO_ARG2(ctx);
	emit_ssl_event(buf, len, 0);
	return 0;
}

// ─── Go TLS: crypto/tls.(*Conn).Read ────────────────────────────
// Signature (Go register ABI): func (c *Conn) Read(b []byte) (int, error)
//   GO_ARG1 = b.data (slice data pointer — buffer for decrypted bytes)
//   GO_RC0  = n (bytes read, at return)
//
// Read는 실제 읽은 바이트 수(n)가 리턴값이므로 두 단계로 처리한다:
//   entry: 버퍼 포인터를 맵에 저장
//   ret  : RET 명령어에 직접 부착한 uprobe에서 n을 읽고 emit
//          (uretprobe 대신 uprobe를 RET 오프셋에 직접 부착 — Go copystack 크래시 방지)

SEC("uprobe/go_tls_read")
int uprobe_go_tls_read_entry(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_buf_args_t a = {};
	a.buf = GO_ARG1(ctx);
	bpf_map_update_elem(&active_go_tls_read_args, &id, &a, BPF_ANY);
	return 0;
}

// uprobe/go_tls_read_ret: RET 명령어 위치에 직접 부착되는 probe.
// uretprobe와 달리 스택의 리턴 주소를 교체하지 않으므로 Go 런타임과 충돌하지 않는다.
SEC("uprobe/go_tls_read_ret")
int uprobe_go_tls_read_ret(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_buf_args_t *a = bpf_map_lookup_elem(&active_go_tls_read_args, &id);
	if (a)
		emit_ssl_event(a->buf, GO_RC0(ctx), 1);
	bpf_map_delete_elem(&active_go_tls_read_args, &id);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
