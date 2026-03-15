// Package model은 BPF 커널 코드와 Go 유저스페이스 사이에서 공유되는
// 데이터 구조를 정의한다.
//
// 역할:
//   BPF 프로그램(nefi_trace.c, ssl_trace.c)이 커널에서 캡처한 이벤트를
//   ringbuf에 바이너리로 써 넣으면, Go에서 그 바이너리를 이 구조체로
//   그대로 읽어낸다.
//
// 중요 제약:
//   DataEvent 구조체의 필드 순서와 크기는 C의 data_event_t와 정확히 일치해야 한다.
//   한 바이트라도 어긋나면 모든 필드가 잘못된 값으로 읽힌다.
//
// 흐름:
//   커널 BPF → ringbuf에 data_event_t(4143 bytes) 저장
//   → loader.go가 binary.LittleEndian으로 읽음
//   → DataEvent 구조체로 변환
//   → main.go에서 출력
package model

import "fmt"

const MaxMsgSize = 4096

// Protocol matches the BPF enum protocol_t (Pixie-compatible numbering).
type Protocol uint8

const (
	ProtoUnknown Protocol = 0
	ProtoHTTP    Protocol = 1
	ProtoHTTP2   Protocol = 2
	ProtoMySQL   Protocol = 3
	ProtoCQL     Protocol = 4
	ProtoPgSQL   Protocol = 5
	ProtoDNS     Protocol = 6
	ProtoRedis   Protocol = 7
	ProtoNATS    Protocol = 8
	ProtoMongo   Protocol = 9
	ProtoKafka   Protocol = 10
	ProtoMux     Protocol = 11
	ProtoAMQP    Protocol = 12
	ProtoTLS     Protocol = 13
)

var protoNames = [14]string{
	"UNKNOWN", "HTTP", "HTTP2", "MySQL",
	"CQL", "PgSQL", "DNS", "Redis",
	"NATS", "Mongo", "Kafka", "Mux",
	"AMQP", "TLS",
}

func (p Protocol) String() string {
	if int(p) < len(protoNames) {
		return protoNames[p]
	}
	return "UNKNOWN"
}

// MsgType matches the BPF enum msg_type_t.
type MsgType uint8

const (
	MsgUnknown  MsgType = 0
	MsgRequest  MsgType = 1
	MsgResponse MsgType = 2
)

func (m MsgType) String() string {
	switch m {
	case MsgRequest:
		return "REQ"
	case MsgResponse:
		return "RES"
	default:
		return "UNK"
	}
}

// DataEvent matches the packed BPF struct data_event_t.
// Field order and sizes must exactly match the C definition.
//
// C layout (packed, 4143 bytes total):
//   u64 timestamp_ns  u32 pid  u32 fd  u32 msg_size
//   u8 direction  u8 protocol  u8 msg_type  char comm[16]
//   u32 remote_ip  u16 remote_port  u16 _pad  char msg[4096]
type DataEvent struct {
	TimestampNs uint64
	PID         uint32
	FD          uint32
	MsgSize     uint32
	Direction   uint8 // 0 = send, 1 = recv
	Protocol    Protocol
	MsgType     MsgType
	Comm        [16]byte
	RemoteIP    uint32  // host byte order; 0 if unknown
	RemotePort  uint16  // host byte order; 0 if unknown
	Pad_        [2]byte // padding; exported because encoding/binary cannot set unexported fields
	Msg         [MaxMsgSize]byte
}

// CommString returns the process name with null bytes trimmed.
func (e *DataEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// Payload returns the captured message bytes (up to MsgSize).
func (e *DataEvent) Payload() []byte {
	n := e.MsgSize
	if n > MaxMsgSize {
		n = MaxMsgSize
	}
	return e.Msg[:n]
}

// DirectionString returns "SEND" or "RECV".
func (e *DataEvent) DirectionString() string {
	if e.Direction == 0 {
		return "SEND >>>"
	}
	return "RECV <<<"
}

// RemoteIPString returns the remote IP as a dotted-decimal string.
// RemoteIP is stored in host byte order after bpf_ntohl conversion,
// so the most-significant byte is the first octet.
func (e *DataEvent) RemoteIPString() string {
	if e.RemoteIP == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		(e.RemoteIP>>24)&0xff,
		(e.RemoteIP>>16)&0xff,
		(e.RemoteIP>>8)&0xff,
		e.RemoteIP&0xff,
	)
}
