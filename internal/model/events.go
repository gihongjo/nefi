package model

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
type DataEvent struct {
	TimestampNs uint64
	PID         uint32
	FD          uint32
	MsgSize     uint32
	Direction   uint8 // 0 = send, 1 = recv
	Protocol    Protocol
	MsgType     MsgType
	Comm        [16]byte
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
