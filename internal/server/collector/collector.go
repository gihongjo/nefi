// Package collector는 nefi-agent로부터 이벤트를 수신하는 gRPC 서비스를 구현한다.
//
// 역할:
//   NefiCollector.SendEvents: agent가 클라이언트 스트리밍으로 TraceEvent를 push하면
//   HTTP 요청/응답을 연결(fd)단위로 추적해 메타데이터를 보강한 뒤 Store에 저장한다.
//
// HTTP 연결 추적:
//   요청 이벤트(method/path 있음, status 없음) → connTracker에 {pod, pid, fd} → {method, path} 저장
//   응답 이벤트(status 있음, method 없음)      → connTracker에서 꺼내 method/path 채움
//   이를 통해 응답 이벤트에도 엔드포인트 정보가 기록된다.
package collector

import (
	"io"
	"log"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/server/httpparse"
	"github.com/gihongjo/nefi/internal/server/store"
	"google.golang.org/grpc/peer"
)

// Service는 NefiCollectorServer 인터페이스를 구현한다.
type Service struct {
	nefiv1.UnimplementedNefiCollectorServer
	store   store.Store
	tracker *connTracker
}

// New는 주어진 Store를 사용하는 CollectorService를 반환한다.
func New(s store.Store) *Service {
	return &Service{
		store:   s,
		tracker: newConnTracker(),
	}
}

// SendEvents는 agent의 이벤트 스트림을 수신한다.
func (s *Service) SendEvents(stream nefiv1.NefiCollector_SendEventsServer) error {
	addr := ""
	if p, ok := peer.FromContext(stream.Context()); ok {
		addr = p.Addr.String()
	}
	log.Printf("[collector] agent connected: %s", addr)

	var received uint64
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[collector] stream error from %s: %v", addr, err)
			return err
		}
		s.enrichHTTP(event)
		s.store.Add(event)
		received++
	}

	log.Printf("[collector] agent %s disconnected — received %d events", addr, received)
	return stream.SendAndClose(&nefiv1.CollectSummary{Received: received})
}

// enrichHTTP는 HTTP 이벤트의 payload를 파싱해 메타데이터 필드를 채운다.
//
// 요청 이벤트: method/path를 connTracker에 저장.
// 응답 이벤트: connTracker에서 같은 연결의 method/path를 꺼내 채움.
func (s *Service) enrichHTTP(event *nefiv1.TraceEvent) {
	if event.Protocol != 1 && event.Protocol != 13 {
		return
	}
	parsed := httpparse.Parse(event.Payload)
	if parsed == nil {
		return
	}

	key := connKey{PodName: event.PodName, PID: event.Pid, FD: event.Fd}

	if parsed.Method != "" {
		// 요청 이벤트: 이후 응답과 매핑하기 위해 캐시에 저장
		s.tracker.set(key, parsed.Method, parsed.Path)
		event.HttpMethod = parsed.Method
		event.HttpPath = parsed.Path
		event.HttpContentType = parsed.ContentType
		return
	}

	if parsed.StatusCode > 0 {
		// 응답 이벤트: 같은 연결의 요청 메타데이터를 꺼내 채움
		event.HttpStatus = parsed.StatusCode
		event.HttpContentType = parsed.ContentType
		if method, path, ok := s.tracker.pop(key); ok {
			event.HttpMethod = method
			event.HttpPath = path
		}
	}
}
