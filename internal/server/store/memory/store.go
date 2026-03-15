// Package memory는 인메모리 ring buffer 기반 Store 구현이다.
//
// 동작 방식:
//   - Add: ring buffer에 이벤트 저장 + 모든 구독자 채널에 비블로킹 전송
//   - ring buffer가 가득 차면 가장 오래된 이벤트를 덮어씀
//   - 구독자 채널이 느리면 이벤트를 drop (backpressure 없음)
package memory

import (
	"sync"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
)

const subscriberChanSize = 256

// Store는 인메모리 ring buffer + 구독자 맵으로 구성된다.
type Store struct {
	mu          sync.RWMutex
	ring        []*nefiv1.TraceEvent
	capacity    int
	head        int // 다음 쓰기 위치 (항상 0 ≤ head < capacity)
	count       int // 저장된 이벤트 수 (최대 capacity)
	closed      bool
	subscribers map[chan *nefiv1.TraceEvent]struct{}
}

// New는 주어진 capacity의 인메모리 Store를 반환한다.
func New(capacity int) *Store {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Store{
		ring:        make([]*nefiv1.TraceEvent, capacity),
		capacity:    capacity,
		subscribers: make(map[chan *nefiv1.TraceEvent]struct{}),
	}
}

// Add는 이벤트를 ring buffer에 저장하고 구독자에게 전파한다.
func (s *Store) Add(event *nefiv1.TraceEvent) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.ring[s.head] = event
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
	// 구독자 목록 복사 후 뮤텍스 해제 (채널 send 중 데드락 방지)
	subs := make([]chan *nefiv1.TraceEvent, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- event:
		default:
			// 구독자가 느리면 drop (실시간 모니터링 특성상 허용)
		}
	}
}

// Subscribe는 새 이벤트 구독 채널을 반환한다.
func (s *Store) Subscribe() <-chan *nefiv1.TraceEvent {
	ch := make(chan *nefiv1.TraceEvent, subscriberChanSize)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

// Unsubscribe는 구독 채널을 해제하고 닫는다.
func (s *Store) Unsubscribe(ch <-chan *nefiv1.TraceEvent) {
	s.mu.Lock()
	for k := range s.subscribers {
		if k == ch {
			delete(s.subscribers, k)
			close(k)
			break
		}
	}
	s.mu.Unlock()
}

// Recent는 최근 n개 이벤트를 오래된 것부터 반환한다.
func (s *Store) Recent(n int) []*nefiv1.TraceEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n <= 0 || s.count == 0 {
		return []*nefiv1.TraceEvent{}
	}
	if n > s.count {
		n = s.count
	}

	result := make([]*nefiv1.TraceEvent, n)
	// head는 다음 쓰기 위치 → (head - count + capacity) % capacity 가 가장 오래된 위치
	start := ((s.head - s.count) + s.capacity) % s.capacity
	for i := 0; i < n; i++ {
		// n개 중 최신 n개: (count - n)개 건너뜀
		idx := (start + (s.count - n) + i) % s.capacity
		result[i] = s.ring[idx]
	}
	return result
}

// Close는 모든 구독 채널을 닫는다.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = make(map[chan *nefiv1.TraceEvent]struct{})
}
