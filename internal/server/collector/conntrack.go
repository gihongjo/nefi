package collector

import (
	"sync"
	"time"
)

const connTTL = 30 * time.Second

// connKey는 하나의 TCP 연결을 식별하는 키다.
// 동일 fd가 다른 연결에 재사용될 수 있으므로 PodName+PID+FD 조합을 사용한다.
type connKey struct {
	PodName string
	PID     uint32
	FD      uint32
}

type connEntry struct {
	method          string
	path            string
	reqTimestampNs  uint64
	expiresAt       time.Time
}

// connTracker는 HTTP 요청(method/path)을 fd 단위로 캐시해두고,
// 응답 이벤트가 오면 해당 요청의 메타데이터를 꺼내 쓸 수 있게 한다.
type connTracker struct {
	mu    sync.Mutex
	cache map[connKey]connEntry
}

func newConnTracker() *connTracker {
	t := &connTracker{cache: make(map[connKey]connEntry)}
	go t.cleanup()
	return t
}

// set은 요청 이벤트의 method/path/timestamp를 연결 키에 저장한다.
func (t *connTracker) set(key connKey, method, path string, reqTimestampNs uint64) {
	t.mu.Lock()
	t.cache[key] = connEntry{
		method:         method,
		path:           path,
		reqTimestampNs: reqTimestampNs,
		expiresAt:      time.Now().Add(connTTL),
	}
	t.mu.Unlock()
}

// pop은 연결 키에 저장된 method/path/timestamp를 꺼내고 캐시에서 제거한다.
func (t *connTracker) pop(key connKey) (method, path string, reqTimestampNs uint64, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, exists := t.cache[key]
	if !exists {
		return "", "", 0, false
	}
	delete(t.cache, key)
	return e.method, e.path, e.reqTimestampNs, true
}

// cleanup은 10초마다 만료된 항목을 제거한다.
// 응답 없이 연결이 끊긴 경우의 메모리 누수를 방지한다.
func (t *connTracker) cleanup() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		t.mu.Lock()
		for k, e := range t.cache {
			if now.After(e.expiresAt) {
				delete(t.cache, k)
			}
		}
		t.mu.Unlock()
	}
}
