// SPDX-License-Identifier: GPL-2.0
//
// nefi_trace.c — libbpf/CO-RE socket data capture
// Traces socket I/O via syscall tracepoints and captures payload.
// Protocol detection ported from Pixie's protocol_inference.h.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// byte order helpers — bpf_endian.h가 없는 환경을 위한 fallback
// __builtin_bswap*는 clang이 항상 인라인으로 처리하므로 BPF verifier 거부 없음
#ifndef bpf_ntohl
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#endif

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef long long      s64;
typedef int            s32;
typedef signed char    s8;
typedef short          s16;

#define MAX_MSG_SIZE 4096
#define PROBE_BUF_SIZE 64
#define AF_INET 2

// ─── Network address structs ────────────────────────────────────

struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;   // network byte order
	u32 sin_addr;   // network byte order
	u8  sin_zero[8];
};

// ─── Tracepoint context structs ─────────────────────────────────

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

// ─── Protocol & message type enums (Pixie-compatible) ───────────

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

enum msg_type_t {
	MSG_UNKNOWN  = 0,
	MSG_REQUEST  = 1,
	MSG_RESPONSE = 2,
};

// ─── Data structures ────────────────────────────────────────────

struct data_event_t {
	u64  timestamp_ns;
	u32  pid;
	u32  fd;
	u32  msg_size;
	u8   direction; // 0 = send, 1 = recv
	u8   protocol;
	u8   msg_type;  // 0 = unknown, 1 = request, 2 = response
	char comm[16];
	u32  remote_ip;   // host byte order (bpf_ntohl applied)
	u16  remote_port; // host byte order (bpf_ntohs applied)
	u16  _pad;
	char msg[MAX_MSG_SIZE];
} __attribute__((packed));

struct args_t {
	u64 buf; // userspace buffer pointer
	u32 fd;
};

// Per-connection remote endpoint info (populated on accept/connect).
struct conn_info_t {
	u32 remote_ip;   // host byte order
	u16 remote_port; // host byte order
	u16 _pad;
};

// Saved sockaddr pointer across accept4/accept enter→exit.
struct accept_args_t {
	u64 sockaddr_ptr;
};

// Per-connection state for stateful protocol detection (MySQL, Kafka).
struct conn_state_t {
	u8   protocol;
	u32  prev_count;
	char prev_buf[4];
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
	__uint(max_entries, 65536);
	__type(key, u64); // pid_tgid
	__type(value, struct args_t);
} active_send_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, struct args_t);
} active_recv_args SEC(".maps");

// Connection state map for stateful protocol detection.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);  // pid<<32 | fd
	__type(value, struct conn_state_t);
} conn_state SEC(".maps");

// Remote endpoint info per connection.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);  // pid<<32 | fd
	__type(value, struct conn_info_t);
} conn_info SEC(".maps");

// Saves sockaddr pointer from accept4/accept enter for use in exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);  // pid_tgid
	__type(value, struct accept_args_t);
} active_accept_args SEC(".maps");

// ─── Helpers (ported from Pixie bpf_tools/utils.h) ──────────────

static __always_inline s32 read_big_endian_s32(const char *buf)
{
	return ((s32)(u8)buf[0] << 24) | ((s32)(u8)buf[1] << 16) |
	       ((s32)(u8)buf[2] << 8)  | (s32)(u8)buf[3];
}

static __always_inline s16 read_big_endian_s16(const char *buf)
{
	return ((s16)(u8)buf[0] << 8) | (s16)(u8)buf[1];
}

// ─── Protocol detection (ported from Pixie protocol_inference.h) ─

// HTTP (Pixie: infer_http_message)
static __noinline u8 infer_http(const char *buf, u32 count)
{
	if (count < 16)
		return MSG_UNKNOWN;

	// Response: HTTP/...
	if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P')
		return MSG_RESPONSE;
	// GET
	if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T')
		return MSG_REQUEST;
	// HEAD
	if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D')
		return MSG_REQUEST;
	// POST
	if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T')
		return MSG_REQUEST;
	// PUT
	if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T')
		return MSG_REQUEST;
	// DELETE
	if (count >= 16 && buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' &&
	    buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E')
		return MSG_REQUEST;
	// PATCH
	if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' &&
	    buf[4] == 'H')
		return MSG_REQUEST;
	// OPTIONS
	if (count >= 16 && buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T')
		return MSG_REQUEST;
	// CONNECT
	if (count >= 16 && buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' &&
	    buf[3] == 'N')
		return MSG_REQUEST;

	return MSG_UNKNOWN;
}

// TLS (Pixie: infer_tls_message)
static __noinline u8 infer_tls(const char *buf, u32 count)
{
	if (count < 6)
		return MSG_UNKNOWN;

	u8 content_type = (u8)buf[0];
	if (content_type != 0x16) // Handshake
		return MSG_UNKNOWN;

	u16 version = ((u16)(u8)buf[1] << 8) | (u8)buf[2];
	if (version < 0x0300 || version > 0x0304)
		return MSG_UNKNOWN;

	u8 handshake_type = (u8)buf[5];
	if (handshake_type == 2)
		return MSG_RESPONSE; // ServerHello
	if (handshake_type == 1)
		return MSG_REQUEST; // ClientHello

	return MSG_UNKNOWN;
}

// CQL / Cassandra (Pixie: infer_cql_message)
static __noinline u8 infer_cql(const char *buf, u32 count)
{
	if (count < 9)
		return MSG_UNKNOWN;

	u8 request = ((u8)buf[0] & 0x80) == 0x00;
	u8 version = (u8)buf[0] & 0x7f;
	u8 flags   = (u8)buf[1];
	u8 opcode  = (u8)buf[4];

	if (version < 3 || version > 5)
		return MSG_UNKNOWN;
	if ((flags & 0xf0) != 0)
		return MSG_UNKNOWN;

	s32 length = read_big_endian_s32(buf + 5);
	if (length > 10000)
		return MSG_UNKNOWN;

	// Request opcodes
	if (opcode == 0x01 || opcode == 0x05 || opcode == 0x07 ||
	    opcode == 0x09 || opcode == 0x0a || opcode == 0x0b ||
	    opcode == 0x0d || opcode == 0x0f)
		return request ? MSG_REQUEST : MSG_UNKNOWN;

	// Response opcodes
	if (opcode == 0x00 || opcode == 0x02 || opcode == 0x03 ||
	    opcode == 0x06 || opcode == 0x08 || opcode == 0x0c ||
	    opcode == 0x0e || opcode == 0x10)
		return !request ? MSG_RESPONSE : MSG_UNKNOWN;

	return MSG_UNKNOWN;
}

// MongoDB (Pixie: infer_mongo_message)
static __noinline u8 infer_mongo(const char *buf, u32 count)
{
	if (count < 16)
		return MSG_UNKNOWN;

	s32 msg_len    = (s32)((u32)(u8)buf[0] | ((u32)(u8)buf[1] << 8) |
	                 ((u32)(u8)buf[2] << 16) | ((u32)(u8)buf[3] << 24));
	s32 request_id = (s32)((u32)(u8)buf[4] | ((u32)(u8)buf[5] << 8) |
	                 ((u32)(u8)buf[6] << 16) | ((u32)(u8)buf[7] << 24));
	s32 response_to = (s32)((u32)(u8)buf[8] | ((u32)(u8)buf[9] << 8) |
	                  ((u32)(u8)buf[10] << 16) | ((u32)(u8)buf[11] << 24));
	s32 opcode     = (s32)((u32)(u8)buf[12] | ((u32)(u8)buf[13] << 8) |
	                 ((u32)(u8)buf[14] << 16) | ((u32)(u8)buf[15] << 24));

	if (msg_len < 16)
		return MSG_UNKNOWN;
	if (request_id < 0)
		return MSG_UNKNOWN;

	// Valid opcodes: OP_UPDATE(2001)..OP_KILL_CURSORS(2007), OP_COMPRESSED(2012), OP_MSG(2013)
	if (opcode == 2001 || opcode == 2002 || opcode == 2003 || opcode == 2004 ||
	    opcode == 2005 || opcode == 2006 || opcode == 2007 ||
	    opcode == 2012 || opcode == 2013) {
		if (response_to == 0)
			return MSG_REQUEST;
	}

	return MSG_UNKNOWN;
}

// PostgreSQL (Pixie: infer_pgsql_message)
static __noinline u8 infer_pgsql(const char *buf, u32 count)
{
	// Startup message: 4-byte length + protocol version 3.0
	if (count >= 12) {
		s32 length = read_big_endian_s32(buf);
		if (length >= 12 && length <= 10240) {
			if ((u8)buf[4] == 0x00 && (u8)buf[5] == 0x03 &&
			    (u8)buf[6] == 0x00 && (u8)buf[7] == 0x00) {
				// Verify key starts with alpha chars
				if ((u8)buf[8] >= 'A' && (u8)buf[9] >= 'A' &&
				    (u8)buf[10] >= 'A')
					return MSG_REQUEST;
			}
		}
	}

	// Query message: tag 'Q' + length
	if (count >= 5 && (u8)buf[0] == 'Q') {
		s32 len = read_big_endian_s32(buf + 1);
		if (len >= 8 && len <= 30000)
			return MSG_REQUEST;
	}

	return MSG_UNKNOWN;
}

// MySQL (Pixie: infer_mysql_message — with conn_state for split reads)
static __noinline u8 infer_mysql(const char *buf, u32 count,
				 struct conn_state_t *cs)
{
	u8 use_prev = 0;
	if (cs && cs->prev_count == 4) {
		u32 expected = (u32)(u8)cs->prev_buf[0] |
			       ((u32)(u8)cs->prev_buf[1] << 8) |
			       ((u32)(u8)cs->prev_buf[2] << 16);
		if (expected == count)
			use_prev = 1;
	}

	u32 total = use_prev ? count + 4 : count;
	if (total < 5)
		return MSG_UNKNOWN;

	u32 len;
	u8 seq, com;

	if (use_prev) {
		len = (u32)(u8)cs->prev_buf[0] |
		      ((u32)(u8)cs->prev_buf[1] << 8) |
		      ((u32)(u8)cs->prev_buf[2] << 16);
		seq = (u8)cs->prev_buf[3];
		com = (u8)buf[0];
	} else {
		len = (u32)(u8)buf[0] | ((u32)(u8)buf[1] << 8) |
		      ((u32)(u8)buf[2] << 16);
		seq = (u8)buf[3];
		com = (u8)buf[4];
	}

	if (seq != 0)
		return MSG_UNKNOWN;
	if (len == 0 || len > 10000)
		return MSG_UNKNOWN;

	// COM_QUERY(3), COM_CONNECT(0x0b), COM_STMT_PREPARE(0x16),
	// COM_STMT_EXECUTE(0x17), COM_STMT_CLOSE(0x19)
	if (com == 0x03 || com == 0x0b || com == 0x16 ||
	    com == 0x17 || com == 0x19)
		return MSG_REQUEST;

	return MSG_UNKNOWN;
}

// Kafka (Pixie: infer_kafka_message — with conn_state for split reads)
static __noinline u8 infer_kafka(const char *buf, u32 count,
				 struct conn_state_t *cs)
{
	u8 use_prev = 0;
	if (cs && cs->prev_count == 4) {
		s32 expected = read_big_endian_s32(cs->prev_buf);
		if (expected > 0 && (u32)expected == count)
			use_prev = 1;
	}

	u32 total = use_prev ? count + 4 : count;
	if (total < 12)
		return MSG_UNKNOWN;

	s32 msg_size;
	const char *req_buf;

	if (use_prev) {
		msg_size = (s32)total;
		req_buf = buf;
	} else {
		msg_size = read_big_endian_s32(buf) + 4;
		req_buf = buf + 4;
	}

	if (msg_size < 0 || (u32)msg_size != total)
		return MSG_UNKNOWN;

	s16 api_key = read_big_endian_s16(req_buf);
	s16 api_ver = read_big_endian_s16(req_buf + 2);
	s32 corr_id = read_big_endian_s32(req_buf + 4);

	if (api_key < 0 || api_key > 62)
		return MSG_UNKNOWN;
	if (api_ver < 0 || api_ver > 12)
		return MSG_UNKNOWN;
	if (corr_id < 0)
		return MSG_UNKNOWN;

	return MSG_REQUEST;
}

// AMQP (Pixie: infer_amqp_message)
static __noinline u8 infer_amqp(const char *buf, u32 count)
{
	if (count < 8)
		return MSG_UNKNOWN;

	u8 frame_type = (u8)buf[0];
	if (frame_type != 1) // Method frame
		return MSG_UNKNOWN;

	s16 class_id  = read_big_endian_s16(buf + 7);
	s16 method_id = read_big_endian_s16(buf + 9);

	// Connection.Start / Connection.StartOk
	if (class_id == 10 && method_id == 10)
		return MSG_REQUEST;
	if (class_id == 10 && method_id == 11)
		return MSG_RESPONSE;
	// Basic.Publish / Basic.Deliver
	if (class_id == 60 && method_id == 40)
		return MSG_REQUEST;
	if (class_id == 60 && method_id == 60)
		return MSG_RESPONSE;

	return MSG_UNKNOWN;
}

// DNS (Pixie: infer_dns_message)
static __noinline u8 infer_dns(const char *buf, u32 count)
{
	if (count < 12 || count > 512)
		return MSG_UNKNOWN;

	u16 flags       = ((u16)(u8)buf[2] << 8) | (u8)buf[3];
	u16 num_questions = ((u16)(u8)buf[4] << 8) | (u8)buf[5];
	u16 num_answers = ((u16)(u8)buf[6] << 8) | (u8)buf[7];
	u16 num_auth    = ((u16)(u8)buf[8] << 8) | (u8)buf[9];
	u16 num_addl    = ((u16)(u8)buf[10] << 8) | (u8)buf[11];

	u8 qr     = (flags >> 15) & 0x1;
	u8 opcode = (flags >> 11) & 0xf;
	u8 zero   = (flags >> 6) & 0x1;

	if (zero != 0)
		return MSG_UNKNOWN;
	if (opcode != 0)
		return MSG_UNKNOWN;
	if (num_questions == 0 || num_questions > 10)
		return MSG_UNKNOWN;

	u32 num_rr = num_questions + num_answers + num_auth + num_addl;
	if (num_rr > 25)
		return MSG_UNKNOWN;

	return qr == 0 ? MSG_REQUEST : MSG_RESPONSE;
}

// Redis (Pixie: is_redis_message)
static __noinline u8 infer_redis(const char *buf, u32 count)
{
	if (count < 3 || count > PROBE_BUF_SIZE)
		return MSG_UNKNOWN;

	u8 first = (u8)buf[0];
	if (first != '+' && first != '-' && first != ':' &&
	    first != '$' && first != '*')
		return MSG_UNKNOWN;

	// Verify \r\n terminal sequence (bound index for verifier)
	u32 idx = (count - 2) & (PROBE_BUF_SIZE - 1);
	if ((u8)buf[idx] != '\r' || (u8)buf[idx + 1] != '\n')
		return MSG_UNKNOWN;

	// Redis can't distinguish request/response without parsing
	return MSG_REQUEST; // placeholder — direction tells the real story
}

// NATS (Pixie: infer_nats_message)
static __noinline u8 infer_nats(const char *buf, u32 count)
{
	if (count < 3 || count > PROBE_BUF_SIZE)
		return MSG_UNKNOWN;

	// Verify \r\n terminal sequence (bound index for verifier)
	u32 idx = (count - 2) & (PROBE_BUF_SIZE - 1);
	if ((u8)buf[idx] != '\r' || (u8)buf[idx + 1] != '\n')
		return MSG_UNKNOWN;

	// Client commands
	if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' &&
	    buf[3] == 'N' && buf[4] == 'E' && buf[5] == 'C' && buf[6] == 'T')
		return MSG_REQUEST;
	if (buf[0] == 'S' && buf[1] == 'U' && buf[2] == 'B')
		return MSG_REQUEST;
	if (buf[0] == 'U' && buf[1] == 'N' && buf[2] == 'S' &&
	    buf[3] == 'U' && buf[4] == 'B')
		return MSG_REQUEST;
	if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'B')
		return MSG_REQUEST;

	// Server commands
	if (buf[0] == 'I' && buf[1] == 'N' && buf[2] == 'F' && buf[3] == 'O')
		return MSG_RESPONSE;
	if (buf[0] == 'M' && buf[1] == 'S' && buf[2] == 'G')
		return MSG_RESPONSE;
	if (buf[0] == '+' && buf[1] == 'O' && buf[2] == 'K')
		return MSG_RESPONSE;
	if (buf[0] == '-' && buf[1] == 'E' && buf[2] == 'R' && buf[3] == 'R')
		return MSG_RESPONSE;

	return MSG_UNKNOWN;
}

// Mux (Pixie: infer_mux_message)
static __noinline u8 infer_mux(const char *buf, u32 count)
{
	if (count < 8)
		return MSG_UNKNOWN;

	s32 type_and_tag = read_big_endian_s32(buf + 4);
	s8 mtype = (s8)((type_and_tag >> 24) & 0xff);
	u32 tag = type_and_tag & 0xffffff;

	u8 result;
	switch (mtype) {
	case 2:   // Tdispatch
	case 68:  // Tinit
	case 127: // RerrOld
		result = MSG_REQUEST;
		break;
	case -2:   // Rdispatch
	case -68:  // Rinit
	case -128: // Rerr
		result = MSG_RESPONSE;
		break;
	default:
		return MSG_UNKNOWN;
	}

	if (tag < 1 || tag > ((1 << 23) - 1))
		return MSG_UNKNOWN;

	// Tinit/Rinit: verify "mux-framer" string at offset 14
	if (mtype == 68 || mtype == -68) {
		if (count < 24)
			return MSG_UNKNOWN;
		if (buf[14] != 'm' || buf[15] != 'u' || buf[16] != 'x' ||
		    buf[17] != '-' || buf[18] != 'f' || buf[19] != 'r' ||
		    buf[20] != 'a' || buf[21] != 'm' || buf[22] != 'e' ||
		    buf[23] != 'r')
			return MSG_UNKNOWN;
	}

	// Tdispatch: verify "com.twitter" context key at offset 12
	if (mtype == 2) {
		if (count < 23)
			return MSG_UNKNOWN;
		if (buf[12] != 'c' || buf[13] != 'o' || buf[14] != 'm' ||
		    buf[15] != '.' || buf[16] != 't' || buf[17] != 'w' ||
		    buf[18] != 'i' || buf[19] != 't' || buf[20] != 't' ||
		    buf[21] != 'e' || buf[22] != 'r')
			return MSG_UNKNOWN;
	}

	// Rdispatch: verify reply status
	if (mtype == -2) {
		u8 status = (u8)buf[8];
		if (status > 2) // 0=Ok, 1=Error, 2=Nack
			return MSG_UNKNOWN;
	}

	return result;
}

// ─── Master protocol inference (Pixie infer_protocol order) ─────

struct infer_result_t {
	u8 protocol;
	u8 msg_type;
};

static __always_inline struct infer_result_t infer_protocol(
	const char *buf, u32 count, struct conn_state_t *cs)
{
	struct infer_result_t r = {PROTO_UNKNOWN, MSG_UNKNOWN};
	u8 t;

	// Order matches Pixie: TLS → HTTP → CQL → Mongo → PgSQL →
	//                      MySQL → Mux → Kafka → DNS → AMQP → Redis → NATS

	if ((t = infer_tls(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_TLS; r.msg_type = t; return r;
	}
	if ((t = infer_http(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_HTTP; r.msg_type = t; return r;
	}
	if ((t = infer_cql(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_CQL; r.msg_type = t; return r;
	}
	if ((t = infer_mongo(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_MONGO; r.msg_type = t; return r;
	}
	if ((t = infer_pgsql(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_PGSQL; r.msg_type = t; return r;
	}
	if ((t = infer_mysql(buf, count, cs)) != MSG_UNKNOWN) {
		r.protocol = PROTO_MYSQL; r.msg_type = t; return r;
	}
	if ((t = infer_mux(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_MUX; r.msg_type = t; return r;
	}
	if ((t = infer_kafka(buf, count, cs)) != MSG_UNKNOWN) {
		r.protocol = PROTO_KAFKA; r.msg_type = t; return r;
	}
	if ((t = infer_dns(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_DNS; r.msg_type = t; return r;
	}
	if ((t = infer_amqp(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_AMQP; r.msg_type = t; return r;
	}
	if (infer_redis(buf, count) != MSG_UNKNOWN) {
		r.protocol = PROTO_REDIS; r.msg_type = MSG_UNKNOWN; return r;
	}
	if ((t = infer_nats(buf, count)) != MSG_UNKNOWN) {
		r.protocol = PROTO_NATS; r.msg_type = t; return r;
	}

	return r;
}

// ─── Emit helper ────────────────────────────────────────────────

static __always_inline int emit_event(struct args_t *a, long bytes, u8 direction)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 conn_key = ((u64)pid << 32) | (u32)a->fd;

	// ── Phase 1: protocol inference on a small stack buffer ──
	// This keeps all inference branches OUTSIDE the ringbuf alloc window
	// so the verifier can track the alloc_mem pointer without blowing up.
	char probe[PROBE_BUF_SIZE];
	__builtin_memset(probe, 0, PROBE_BUF_SIZE);
	u32 probe_len = (u32)bytes;
	if (probe_len >= PROBE_BUF_SIZE)
		probe_len = PROBE_BUF_SIZE - 1;
	probe_len &= (PROBE_BUF_SIZE - 1); // verifier: prove max 63
	bpf_probe_read_user(probe, probe_len + 1, (void *)a->buf);

	struct conn_state_t *cs = bpf_map_lookup_elem(&conn_state, &conn_key);

	u8 proto;
	u8 mtype;

	if (cs && cs->protocol != PROTO_UNKNOWN) {
		proto = cs->protocol;
		mtype = MSG_UNKNOWN;
	} else {
		struct infer_result_t r = infer_protocol(probe, probe_len, cs);
		proto = r.protocol;
		mtype = r.msg_type;

		if (r.protocol != PROTO_UNKNOWN) {
			struct conn_state_t new_cs = {};
			new_cs.protocol = r.protocol;
			bpf_map_update_elem(&conn_state, &conn_key, &new_cs, BPF_ANY);
		}
	}

	// Save prev_buf for MySQL/Kafka split-read detection
	if (probe_len == 4 && cs == 0) {
		struct conn_state_t new_cs = {};
		new_cs.prev_count = 4;
		new_cs.prev_buf[0] = probe[0];
		new_cs.prev_buf[1] = probe[1];
		new_cs.prev_buf[2] = probe[2];
		new_cs.prev_buf[3] = probe[3];
		bpf_map_update_elem(&conn_state, &conn_key, &new_cs, BPF_ANY);
	} else if (cs) {
		struct conn_state_t new_cs = {};
		new_cs.protocol = cs->protocol;
		new_cs.prev_count = 0;
		bpf_map_update_elem(&conn_state, &conn_key, &new_cs, BPF_ANY);
	}

	// ── Phase 2: ringbuf reserve + payload copy (simple, verifier-friendly) ──
	struct data_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid       = pid;
	event->fd        = a->fd;
	event->direction = direction;
	event->msg_size  = (u32)bytes;
	event->protocol  = proto;
	event->msg_type  = mtype;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	struct conn_info_t *ci = bpf_map_lookup_elem(&conn_info, &conn_key);
	if (ci) {
		event->remote_ip   = ci->remote_ip;
		event->remote_port = ci->remote_port;
	} else {
		event->remote_ip   = 0;
		event->remote_port = 0;
	}
	event->_pad = 0;

	u32 copy = (u32)bytes;
	if (copy > MAX_MSG_SIZE)
		copy = MAX_MSG_SIZE;
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

	// Extract remote IP/port from sockaddr_in.
	u64 addr_ptr = ctx->args[1];
	if (addr_ptr) {
		struct sockaddr_in sa = {};
		bpf_probe_read_user(&sa, sizeof(sa), (void *)addr_ptr);
		if (sa.sin_family == AF_INET) {
			struct conn_info_t ci = {};
			ci.remote_ip   = bpf_ntohl(sa.sin_addr);
			ci.remote_port = bpf_ntohs(sa.sin_port);
			bpf_map_update_elem(&conn_info, &key, &ci, BPF_ANY);
		}
	}
	return 0;
}

// accept4 enter: save sockaddr pointer for exit handler.
SEC("tracepoint/syscalls/sys_enter_accept4")
int tp_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct accept_args_t a = {};
	a.sockaddr_ptr = ctx->args[1]; // struct sockaddr *addr (output param)
	bpf_map_update_elem(&active_accept_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tp_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
	long fd = ctx->ret;
	u64 id  = bpf_get_current_pid_tgid();

	if (fd < 0) {
		bpf_map_delete_elem(&active_accept_args, &id);
		return 0;
	}

	u32 pid = id >> 32;
	u64 key = ((u64)pid << 32) | (u32)fd;
	u8 val  = 1;
	bpf_map_update_elem(&socket_fds, &key, &val, BPF_ANY);

	// Read remote addr written by kernel into the sockaddr output param.
	struct accept_args_t *aa = bpf_map_lookup_elem(&active_accept_args, &id);
	if (aa && aa->sockaddr_ptr) {
		struct sockaddr_in sa = {};
		bpf_probe_read_user(&sa, sizeof(sa), (void *)aa->sockaddr_ptr);
		if (sa.sin_family == AF_INET) {
			struct conn_info_t ci = {};
			ci.remote_ip   = bpf_ntohl(sa.sin_addr);
			ci.remote_port = bpf_ntohs(sa.sin_port);
			bpf_map_update_elem(&conn_info, &key, &ci, BPF_ANY);
		}
	}
	bpf_map_delete_elem(&active_accept_args, &id);
	return 0;
}

// accept (legacy syscall) — some JVM versions use accept() instead of accept4()
SEC("tracepoint/syscalls/sys_enter_accept")
int tp_sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct accept_args_t a = {};
	a.sockaddr_ptr = ctx->args[1];
	bpf_map_update_elem(&active_accept_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tp_sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
	long fd = ctx->ret;
	u64 id  = bpf_get_current_pid_tgid();

	if (fd < 0) {
		bpf_map_delete_elem(&active_accept_args, &id);
		return 0;
	}

	u32 pid = id >> 32;
	u64 key = ((u64)pid << 32) | (u32)fd;
	u8 val  = 1;
	bpf_map_update_elem(&socket_fds, &key, &val, BPF_ANY);

	struct accept_args_t *aa = bpf_map_lookup_elem(&active_accept_args, &id);
	if (aa && aa->sockaddr_ptr) {
		struct sockaddr_in sa = {};
		bpf_probe_read_user(&sa, sizeof(sa), (void *)aa->sockaddr_ptr);
		if (sa.sin_family == AF_INET) {
			struct conn_info_t ci = {};
			ci.remote_ip   = bpf_ntohl(sa.sin_addr);
			ci.remote_port = bpf_ntohs(sa.sin_port);
			bpf_map_update_elem(&conn_info, &key, &ci, BPF_ANY);
		}
	}
	bpf_map_delete_elem(&active_accept_args, &id);
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

// ─── recvmsg ─────────────────────────────────────────────────────
// Java NIO (Tomcat/Spring Boot) may use recvmsg() instead of read()
// for reading from accepted sockets. struct msghdr layout (64-bit):
//   offset  0: void *msg_name   (8 bytes)
//   offset  8: int   msg_namelen (4 bytes) + 4 bytes padding
//   offset 16: struct iovec *msg_iov (8 bytes)  ← we need this
//   offset 24: size_t msg_iovlen
// struct iovec layout:
//   offset 0: void *iov_base (8 bytes)  ← actual buffer pointer
//   offset 8: size_t iov_len

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tp_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	if (fd <= 2)
		return 0;

	u64 sock_key = ((u64)pid << 32) | (u32)fd;
	if (!bpf_map_lookup_elem(&socket_fds, &sock_key))
		return 0;

	// Read msg_iov pointer from msghdr at offset 16.
	u64 msghdr_ptr = ctx->args[1];
	u64 iov_ptr    = 0;
	bpf_probe_read_user(&iov_ptr, sizeof(iov_ptr),
	                    (void *)(msghdr_ptr + 16));
	if (!iov_ptr)
		return 0;

	// Read iov_base (first iovec, offset 0).
	u64 buf = 0;
	bpf_probe_read_user(&buf, sizeof(buf), (void *)iov_ptr);
	if (!buf)
		return 0;

	struct args_t a = {};
	a.buf = buf;
	a.fd  = (u32)fd;
	bpf_map_update_elem(&active_recv_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tp_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx)
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

// ─── readv ───────────────────────────────────────────────────────
// Java NIO may use readv() (scatter-gather read) for socket I/O.
// We capture iovec[0].iov_base as the buffer pointer.

SEC("tracepoint/syscalls/sys_enter_readv")
int tp_sys_enter_readv(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	if (fd <= 2)
		return 0;

	u64 sock_key = ((u64)pid << 32) | (u32)fd;
	if (!bpf_map_lookup_elem(&socket_fds, &sock_key))
		return 0;

	// iovec[0].iov_base is at offset 0 of the first iovec.
	u64 iov_ptr = ctx->args[1];
	u64 buf     = 0;
	bpf_probe_read_user(&buf, sizeof(buf), (void *)iov_ptr);
	if (!buf)
		return 0;

	struct args_t a = {};
	a.buf = buf;
	a.fd  = (u32)fd;
	bpf_map_update_elem(&active_recv_args, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tp_sys_exit_readv(struct trace_event_raw_sys_exit *ctx)
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

// ─── close (cleanup) ────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_close")
int tp_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int fd  = (int)ctx->args[0];

	u64 key = ((u64)pid << 32) | (u32)fd;
	bpf_map_delete_elem(&socket_fds, &key);
	bpf_map_delete_elem(&conn_state, &key);
	bpf_map_delete_elem(&conn_info, &key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
