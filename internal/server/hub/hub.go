// Package hub는 WebSocket 클라이언트에게 이벤트와 집계 통계를 broadcast하는 허브를 구현한다.
//
// 메시지 타입 (type 필드로 구분):
//   {"type":"event", ...}  — raw 캡처 이벤트 (실시간)
//   {"type":"stats", "window_sec":60, "endpoints":[...]}  — 1초마다 슬라이딩 윈도우 집계
//
// WebSocket 엔드포인트: GET /ws
//   - 연결 시 최근 100개 이벤트를 먼저 전송 (히스토리)
//   - 이후 실시간 이벤트 + 매 1초 통계 스트리밍
package hub

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/server/aggregator"
	"github.com/gihongjo/nefi/internal/server/store"
)

const (
	historySize    = 100
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // 개발 편의상 전체 허용
}

// WsEvent는 raw 이벤트 WebSocket 메시지다. Type은 항상 "event".
type WsEvent struct {
	Type            string `json:"type"` // "event"
	TimestampNs     uint64 `json:"ts"`
	PID             uint32 `json:"pid"`
	FD              uint32 `json:"fd"`
	MsgSize         uint32 `json:"msg_size"`
	Direction       uint32 `json:"direction"`   // 0=send, 1=recv
	Protocol        uint32 `json:"protocol"`
	MsgType         uint32 `json:"msg_type"`
	Comm            string `json:"comm"`
	Namespace       string `json:"namespace,omitempty"`
	PodName         string `json:"pod_name,omitempty"`
	NodeName        string `json:"node_name,omitempty"`
	RemoteIP        uint32 `json:"remote_ip,omitempty"`
	RemotePort      uint32 `json:"remote_port,omitempty"`
	RemoteNs        string `json:"remote_ns,omitempty"`
	RemotePod       string `json:"remote_pod,omitempty"`
	Payload         string `json:"payload,omitempty"` // printable ASCII
	HttpMethod      string `json:"http_method,omitempty"`
	HttpPath        string `json:"http_path,omitempty"`
	HttpStatus      int32  `json:"http_status,omitempty"`
	HttpContentType string `json:"http_content_type,omitempty"`
}

// WsStats는 슬라이딩 윈도우 집계 결과 WebSocket 메시지다. Type은 항상 "stats".
type WsStats struct {
	Type      string                    `json:"type"`       // "stats"
	WindowSec int                       `json:"window_sec"` // 집계 윈도우 (초)
	Endpoints []aggregator.EndpointStat `json:"endpoints"`
}

// Hub는 Store와 Aggregator를 구독하고 WebSocket 클라이언트에게 이벤트/통계를 broadcast한다.
type Hub struct {
	store   store.Store
	agg     *aggregator.Aggregator
	sub     <-chan *nefiv1.TraceEvent
	aggSub  <-chan []aggregator.EndpointStat
	clients map[*client]struct{}
	mu      sync.Mutex
	done    chan struct{}
}

type client struct {
	conn *websocket.Conn
	send chan []byte
}

// New는 Hub를 생성하고 Store/Aggregator 구독을 시작한다.
func New(s store.Store, agg *aggregator.Aggregator) *Hub {
	h := &Hub{
		store:   s,
		agg:     agg,
		sub:     s.Subscribe(),
		aggSub:  agg.Subscribe(),
		clients: make(map[*client]struct{}),
		done:    make(chan struct{}),
	}
	go h.run()
	return h
}

// ServeHTTP는 WebSocket 업그레이드 핸들러다.
// GET /ws 로 마운트하면 된다.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[hub] upgrade error: %v", err)
		return
	}

	c := &client{conn: conn, send: make(chan []byte, 256)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()

	// 히스토리 먼저 전송
	for _, ev := range h.store.Recent(historySize) {
		if data, err := marshalEvent(ev); err == nil {
			c.send <- data
		}
	}

	go c.writePump()
	c.readPump(func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
		close(c.send)
	})
}

// Close는 Hub와 Store/Aggregator 구독을 종료한다.
func (h *Hub) Close() {
	close(h.done)
	h.store.Unsubscribe(h.sub)
	h.agg.Unsubscribe(h.aggSub)
}

// run은 Store 이벤트와 Aggregator 통계를 받아 모든 클라이언트에게 전송한다.
func (h *Hub) run() {
	for {
		select {
		case <-h.done:
			return
		case ev, ok := <-h.sub:
			if !ok {
				return
			}
			data, err := marshalEvent(ev)
			if err != nil {
				continue
			}
			h.broadcast(data)
		case stats, ok := <-h.aggSub:
			if !ok {
				return
			}
			data, err := marshalStats(stats)
			if err != nil {
				continue
			}
			h.broadcast(data)
		}
	}
}

func (h *Hub) broadcast(data []byte) {
	h.mu.Lock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			// 클라이언트가 느리면 drop
		}
	}
	h.mu.Unlock()
}

func (c *client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *client) readPump(onClose func()) {
	defer func() {
		onClose()
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}

func marshalStats(stats []aggregator.EndpointStat) ([]byte, error) {
	return json.Marshal(WsStats{
		Type:      "stats",
		WindowSec: aggregator.DefaultWindowSec,
		Endpoints: stats,
	})
}

func marshalEvent(ev *nefiv1.TraceEvent) ([]byte, error) {
	ws := WsEvent{
		Type:        "event",
		TimestampNs: ev.TimestampNs,
		PID:         ev.Pid,
		FD:          ev.Fd,
		MsgSize:     ev.MsgSize,
		Direction:   ev.Direction,
		Protocol:    ev.Protocol,
		MsgType:     ev.MsgType,
		Comm:        ev.Comm,
		Namespace:   ev.Namespace,
		PodName:     ev.PodName,
		NodeName:    ev.NodeName,
		RemoteIP:    ev.RemoteIp,
		RemotePort:  ev.RemotePort,
		RemoteNs:    ev.RemoteNs,
		RemotePod:       ev.RemotePod,
		Payload:         toPrintable(ev.Payload),
		HttpMethod:      ev.HttpMethod,
		HttpPath:        ev.HttpPath,
		HttpStatus:      ev.HttpStatus,
		HttpContentType: ev.HttpContentType,
	}
	return json.Marshal(ws)
}

// toPrintable는 바이너리 페이로드를 출력 가능한 ASCII 문자열로 변환한다.
func toPrintable(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
