// Package store defines the event storage interface.
package store

import (
	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/server/store/memory"
)

// Store는 이벤트 저장소 인터페이스다.
type Store interface {
	Add(event *nefiv1.TraceEvent)
	Subscribe() <-chan *nefiv1.TraceEvent
	Unsubscribe(ch <-chan *nefiv1.TraceEvent)
	Recent(n int) []*nefiv1.TraceEvent
	Close()
}

// New는 인메모리 Store를 반환한다.
func New(capacity int) Store {
	return memory.New(capacity)
}
