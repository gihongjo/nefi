// Package aggregator는 HTTP 이벤트를 1초 단위 bucket으로 집계하는 슬라이딩 윈도우다.
//
// 동작:
//   - Store를 구독해 이벤트를 수신한다.
//   - 현재 초의 bucket에 엔드포인트별 카운터(total/success/error)를 기록한다.
//   - 매 1초마다 window 범위의 bucket을 합산해 구독자에게 전파한다.
//
// 메모리: 최대 300 bucket (5분) × 엔드포인트 수. 트래픽 양과 무관하게 고정 크기.
package aggregator

import (
	"regexp"
	"sync"
	"time"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/server/store"
)

// deploymentPattern은 Kubernetes Deployment pod 이름 패턴이다.
//   <deployment>-<replicaset-hash(9-10)>-<pod-hash(5)>
// ReplicaSet 해시와 pod 해시는 소문자 alphanumeric.
var deploymentPattern = regexp.MustCompile(`^(.+)-[a-z0-9]{9,10}-[a-z0-9]{5}$`)

// statefulSetPattern은 StatefulSet pod 이름 패턴이다.
//   <statefulset>-<ordinal>
var statefulSetPattern = regexp.MustCompile(`^(.+)-\d+$`)

// WorkloadName은 pod 이름에서 workload(Deployment/StatefulSet) 이름을 추출한다.
func WorkloadName(podName string) string {
	if m := deploymentPattern.FindStringSubmatch(podName); m != nil {
		return m[1]
	}
	if m := statefulSetPattern.FindStringSubmatch(podName); m != nil {
		return m[1]
	}
	return podName
}

const (
	maxWindowSec     = 300 // 최대 윈도우: 5분
	DefaultWindowSec = 60  // Subscribe() 기본 윈도우: 60초
	subChanSize      = 4
)

// EndpointKey는 집계 단위 키다.
type EndpointKey struct {
	Namespace string
	PodName   string
	Method    string
	Path      string
}

// Counts는 한 bucket 내 한 엔드포인트의 요청 카운터다.
type Counts struct {
	Total   int32
	Success int32 // 2xx
	Error   int32 // 4xx, 5xx
}

// EndpointStat는 윈도우 집계 결과 하나다.
type EndpointStat struct {
	Namespace    string  `json:"namespace"`
	WorkloadName string  `json:"workload_name"` // Deployment/StatefulSet 이름 (pod 이름에서 파싱)
	PodName      string  `json:"pod_name"`
	Method       string  `json:"method"`
	Path         string  `json:"path"`
	Total        int32   `json:"total"`
	Success      int32   `json:"success"`
	Error        int32   `json:"error"`
	SuccessRate  float64 `json:"success_rate"` // 0.0~100.0
}

type bucket struct {
	sec   int64
	stats map[EndpointKey]Counts
}

// Aggregator는 슬라이딩 윈도우 bucket 집계기다.
type Aggregator struct {
	mu      sync.Mutex
	buckets []bucket
	subs    map[chan []EndpointStat]struct{}
	store   store.Store
	storeSub <-chan *nefiv1.TraceEvent
	done    chan struct{}
}

// New는 store를 구독하고 백그라운드 집계를 시작하는 Aggregator를 반환한다.
func New(s store.Store) *Aggregator {
	a := &Aggregator{
		subs:     make(map[chan []EndpointStat]struct{}),
		store:    s,
		storeSub: s.Subscribe(),
		done:     make(chan struct{}),
	}
	go a.consume()
	go a.tick()
	return a
}

// Snapshot은 주어진 windowSec(1~300) 범위의 집계 결과를 반환한다.
func (a *Aggregator) Snapshot(windowSec int) []EndpointStat {
	if windowSec < 1 {
		windowSec = 1
	}
	if windowSec > maxWindowSec {
		windowSec = maxWindowSec
	}
	cutoff := time.Now().Unix() - int64(windowSec)

	a.mu.Lock()
	merged := make(map[EndpointKey]Counts)
	for _, b := range a.buckets {
		if b.sec <= cutoff {
			continue
		}
		for k, c := range b.stats {
			m := merged[k]
			m.Total += c.Total
			m.Success += c.Success
			m.Error += c.Error
			merged[k] = m
		}
	}
	a.mu.Unlock()

	result := make([]EndpointStat, 0, len(merged))
	for k, c := range merged {
		rate := 0.0
		if c.Total > 0 {
			rate = float64(c.Success) / float64(c.Total) * 100
		}
		result = append(result, EndpointStat{
			Namespace:    k.Namespace,
			WorkloadName: WorkloadName(k.PodName),
			PodName:      k.PodName,
			Method:       k.Method,
			Path:         k.Path,
			Total:        c.Total,
			Success:      c.Success,
			Error:        c.Error,
			SuccessRate:  rate,
		})
	}
	return result
}

// Subscribe는 매 1초마다 defaultWindowSec 범위의 집계 결과를 받는 채널을 반환한다.
func (a *Aggregator) Subscribe() <-chan []EndpointStat {
	ch := make(chan []EndpointStat, subChanSize)
	a.mu.Lock()
	a.subs[ch] = struct{}{}
	a.mu.Unlock()
	return ch
}

// Unsubscribe는 구독 채널을 해제한다.
func (a *Aggregator) Unsubscribe(ch <-chan []EndpointStat) {
	a.mu.Lock()
	for k := range a.subs {
		if k == ch {
			delete(a.subs, k)
			close(k)
			break
		}
	}
	a.mu.Unlock()
}

// Close는 집계를 중단하고 store 구독을 해제한다.
func (a *Aggregator) Close() {
	close(a.done)
	a.store.Unsubscribe(a.storeSub)
}

// consume은 store 구독 채널에서 이벤트를 받아 bucket에 기록한다.
func (a *Aggregator) consume() {
	for {
		select {
		case <-a.done:
			return
		case ev, ok := <-a.storeSub:
			if !ok {
				return
			}
			a.record(ev)
		}
	}
}

// record는 HTTP 응답 이벤트를 현재 초의 bucket에 기록한다.
// status가 없는 이벤트(요청)는 집계에서 제외한다.
// collector의 connTracker가 응답 이벤트에 요청의 method/path를 채워주므로
// 응답만 집계해도 엔드포인트별 성공률을 올바르게 산출할 수 있다.
func (a *Aggregator) record(ev *nefiv1.TraceEvent) {
	if ev.HttpStatus == 0 {
		return
	}
	key := EndpointKey{
		Namespace: ev.Namespace,
		PodName:   ev.PodName,
		Method:    ev.HttpMethod,
		Path:      ev.HttpPath,
	}
	sec := time.Now().Unix()

	a.mu.Lock()
	defer a.mu.Unlock()

	// 현재 초 bucket이 없으면 추가
	if len(a.buckets) == 0 || a.buckets[len(a.buckets)-1].sec != sec {
		a.buckets = append(a.buckets, bucket{
			sec:   sec,
			stats: make(map[EndpointKey]Counts),
		})
	}
	b := &a.buckets[len(a.buckets)-1]
	c := b.stats[key]
	c.Total++
	if ev.HttpStatus >= 200 && ev.HttpStatus < 400 {
		c.Success++
	} else if ev.HttpStatus >= 400 {
		c.Error++
	}
	b.stats[key] = c
}

// tick은 매 1초마다 오래된 bucket을 제거하고 구독자에게 stats를 전파한다.
func (a *Aggregator) tick() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-ticker.C:
			a.prune()
			stats := a.Snapshot(DefaultWindowSec)
			a.mu.Lock()
			subs := make([]chan []EndpointStat, 0, len(a.subs))
			for ch := range a.subs {
				subs = append(subs, ch)
			}
			a.mu.Unlock()
			for _, ch := range subs {
				select {
				case ch <- stats:
				default:
				}
			}
		}
	}
}

// prune은 maxWindowSec보다 오래된 bucket을 제거한다.
func (a *Aggregator) prune() {
	cutoff := time.Now().Unix() - maxWindowSec
	a.mu.Lock()
	defer a.mu.Unlock()
	i := 0
	for i < len(a.buckets) && a.buckets[i].sec <= cutoff {
		i++
	}
	if i > 0 {
		a.buckets = a.buckets[i:]
	}
}
