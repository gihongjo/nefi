// Package grpc는 nefi-agent에서 nefi-server로 이벤트를 전송하는 gRPC 클라이언트다.
//
// 역할:
//   agent의 이벤트 루프에서 DataEvent를 받아 TraceEvent proto로 변환한 뒤,
//   nefi-server의 NefiCollector.SendEvents 스트림에 전송한다.
//
// 재연결 전략:
//   연결이 끊기면 exponential backoff(최대 30초)로 재연결을 시도한다.
//   server가 잠시 내려가도 agent는 계속 캡처를 유지한다.
package grpc

import (
	"context"
	"log"
	"time"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	sendChanSize   = 512
)

// Sender는 nefi-server로 이벤트를 스트리밍하는 gRPC 클라이언트다.
type Sender struct {
	serverAddr string
	nodeName   string
	ch         chan *nefiv1.TraceEvent
	done       chan struct{}
}

// New는 Sender를 생성하고 백그라운드 전송 고루틴을 시작한다.
// serverAddr: nefi-server gRPC 주소 (예: "nefi-server:9090")
// nodeName: 이 agent가 실행 중인 노드 이름
func New(serverAddr, nodeName string) *Sender {
	s := &Sender{
		serverAddr: serverAddr,
		nodeName:   nodeName,
		ch:         make(chan *nefiv1.TraceEvent, sendChanSize),
		done:       make(chan struct{}),
	}
	go s.run()
	return s
}

// Send는 DataEvent를 TraceEvent로 변환해 전송 큐에 넣는다.
// 큐가 가득 차면 이벤트를 drop한다 (캡처 루프 블로킹 방지).
func (s *Sender) Send(ev *model.DataEvent, namespace, podName, remoteNs, remotePod string) {
	proto := &nefiv1.TraceEvent{
		TimestampNs: ev.TimestampNs,
		Pid:         ev.PID,
		Fd:          ev.FD,
		MsgSize:     ev.MsgSize,
		Direction:   uint32(ev.Direction),
		Protocol:    uint32(ev.Protocol),
		MsgType:     uint32(ev.MsgType),
		Comm:        ev.CommString(),
		Namespace:   namespace,
		PodName:     podName,
		NodeName:    s.nodeName,
		RemoteIp:    ev.RemoteIP,
		RemotePort:  uint32(ev.RemotePort),
		RemoteNs:    remoteNs,
		RemotePod:   remotePod,
		Payload:     ev.Payload(),
	}

	select {
	case s.ch <- proto:
	default:
		// 큐 가득 참 → drop
	}
}

// Close는 Sender를 종료하고 gRPC 연결을 닫는다.
func (s *Sender) Close() {
	close(s.done)
}

// run은 server에 연결하고 이벤트를 스트리밍한다.
// 연결이 끊기면 exponential backoff로 재연결한다.
func (s *Sender) run() {
	backoff := initialBackoff
	for {
		select {
		case <-s.done:
			return
		default:
		}

		if err := s.stream(); err != nil {
			log.Printf("[sender] stream error: %v — retrying in %v", err, backoff)
		}

		select {
		case <-s.done:
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (s *Sender) stream() error {
	conn, err := grpc.NewClient(s.serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := nefiv1.NewNefiCollectorClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.SendEvents(ctx)
	if err != nil {
		return err
	}

	log.Printf("[sender] connected to server %s", s.serverAddr)
	// 재연결 성공 시 backoff 리셋은 호출자에서 처리 불가하므로, 채널 drain 없이 진행

	for {
		select {
		case <-s.done:
			_, err := stream.CloseAndRecv()
			return err
		case ev, ok := <-s.ch:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}
