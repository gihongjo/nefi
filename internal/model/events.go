package model

const MaxMsgSize = 512

// DataEvent matches the packed BPF struct data_event_t.
// Field order and sizes must exactly match the C definition.
type DataEvent struct {
	TimestampNs uint64
	PID         uint32
	FD          uint32
	MsgSize     uint32
	Direction   uint8 // 0 = send, 1 = recv
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
