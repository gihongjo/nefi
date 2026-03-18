// Package api는 gin 기반 REST API 핸들러를 제공한다.
//
// 엔드포인트:
//
//	GET /healthz               — 헬스체크
//	GET /api/stats?window=60   — aggregator 슬라이딩 윈도우 집계 결과
//	GET /api/events?limit=100  — store 최근 이벤트 목록
package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/server/aggregator"
	"github.com/gihongjo/nefi/internal/server/store"
)

// ---- Request / Response 타입 ----

type statsQuery struct {
	Window int `form:"window" binding:"omitempty,min=1,max=300"`
}

type eventsQuery struct {
	Limit int `form:"limit" binding:"omitempty,min=1,max=10000"`
}

type statsResponse struct {
	WindowSec int                       `json:"window_sec"`
	Endpoints []aggregator.EndpointStat `json:"endpoints"`
}

type eventsResponse struct {
	Count  int             `json:"count"`
	Events []eventResponse `json:"events"`
}

type eventResponse struct {
	TimestampNs     uint64  `json:"ts"`
	PID             uint32  `json:"pid"`
	FD              uint32  `json:"fd"`
	MsgSize         uint32  `json:"msg_size"`
	Direction       uint32  `json:"direction"`
	Protocol        uint32  `json:"protocol"`
	Comm            string  `json:"comm"`
	Namespace       string  `json:"namespace,omitempty"`
	PodName         string  `json:"pod_name,omitempty"`
	NodeName        string  `json:"node_name,omitempty"`
	HttpMethod      string  `json:"http_method,omitempty"`
	HttpPath        string  `json:"http_path,omitempty"`
	HttpStatus      int32   `json:"http_status,omitempty"`
	HttpContentType string  `json:"http_content_type,omitempty"`
	LatencyMs       float64 `json:"latency_ms,omitempty"` // 레이턴시 (ms), 0이면 미측정
}

// ---- Handler ----

// Handler는 REST API 핸들러 의존성을 보유한다.
type Handler struct {
	store store.Store
	agg   *aggregator.Aggregator
}

// New는 Handler를 생성한다.
func New(s store.Store, agg *aggregator.Aggregator) *Handler {
	return &Handler{store: s, agg: agg}
}

// Register는 라우터에 엔드포인트를 등록한다.
// gin.Engine 대신 gin.IRouter를 받아 RouterGroup에도 마운트 가능하다.
func (h *Handler) Register(r gin.IRouter) {
	r.GET("/healthz", h.healthz)

	v1 := r.Group("/api/v1")
	{
		v1.GET("/stats", h.getStats)
		v1.GET("/events", h.getEvents)
		v1.GET("/topology", h.getTopology)
	}
}

// GET /healthz
func (h *Handler) healthz(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// GET /api/v1/stats?window=60
// window: 1~300 (초), 기본값 60
func (h *Handler) getStats(c *gin.Context) {
	var q statsQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if q.Window == 0 {
		q.Window = aggregator.DefaultWindowSec
	}

	c.JSON(http.StatusOK, statsResponse{
		WindowSec: q.Window,
		Endpoints: h.agg.Snapshot(q.Window),
	})
}

// GET /api/v1/events?limit=100
// limit: 1~10000, 기본값 100
func (h *Handler) getEvents(c *gin.Context) {
	var q eventsQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if q.Limit == 0 {
		q.Limit = 100
	}

	events := h.store.Recent(q.Limit)
	c.JSON(http.StatusOK, eventsResponse{
		Count:  len(events),
		Events: toEventList(events),
	})
}

func toEventList(events []*nefiv1.TraceEvent) []eventResponse {
	result := make([]eventResponse, 0, len(events))
	for _, ev := range events {
		latencyMs := 0.0
		if ev.LatencyNs > 0 {
			latencyMs = float64(ev.LatencyNs) / 1e6
		}
		result = append(result, eventResponse{
			TimestampNs:     ev.TimestampNs,
			PID:             ev.Pid,
			FD:              ev.Fd,
			MsgSize:         ev.MsgSize,
			Direction:       ev.Direction,
			Protocol:        ev.Protocol,
			Comm:            ev.Comm,
			Namespace:       ev.Namespace,
			PodName:         ev.PodName,
			NodeName:        ev.NodeName,
			HttpMethod:      ev.HttpMethod,
			HttpPath:        ev.HttpPath,
			HttpStatus:      ev.HttpStatus,
			HttpContentType: ev.HttpContentType,
			LatencyMs:       latencyMs,
		})
	}
	return result
}

// ---- Topology ----

type topoQuery struct {
	Limit int `form:"limit" binding:"omitempty,min=1,max=50000"`
}

type topoNode struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
}

type topoEdge struct {
	ID           string  `json:"id"`
	Source       string  `json:"source"`
	Target       string  `json:"target"`
	Total        int64   `json:"total"`
	Success      int64   `json:"success"`
	Error        int64   `json:"error"`
	SuccessRate  float64 `json:"success_rate"`
	AvgLatencyMs float64 `json:"avg_latency_ms"` // 평균 레이턴시 (ms), 0이면 미측정
}

type topoResponse struct {
	Nodes []topoNode `json:"nodes"`
	Edges []topoEdge `json:"edges"`
}

type edgeKey struct {
	Src string
	Dst string
}

type edgeCounts struct {
	total        int64
	success      int64
	error        int64
	latencySum   int64 // ns 누적
	latencyCount int64
}

// GET /api/v1/topology?limit=5000
// store의 최근 이벤트에서 workload 간 트래픽 토폴로지를 반환한다.
//
// 노드 식별 우선순위: K8s PodName > Comm (프로세스명)
// 엣지 방향: 요청 방향 (A→B = A가 B를 호출함)
//   - Direction 0(SEND, 응답 송신): 리모트(클라이언트)→로컬(서버) 요청 방향
//   - Direction 1(RECV, 응답 수신): 로컬(클라이언트)→리모트(서버) 요청 방향
func (h *Handler) getTopology(c *gin.Context) {
	var q topoQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if q.Limit == 0 {
		q.Limit = 5000
	}

	events := h.store.Recent(q.Limit)

	nodeSet := make(map[string]topoNode)
	edgeMap := make(map[edgeKey]*edgeCounts)

	for _, ev := range events {
		if ev.HttpStatus == 0 {
			continue
		}

		// 로컬 workload 식별: K8s PodName이 없으면 skip (호스트 프로세스 제외)
		if ev.PodName == "" {
			continue
		}
		localWorkload := aggregator.WorkloadName(ev.PodName)
		localID := localWorkload
		if ev.Namespace != "" {
			localID = ev.Namespace + "/" + localWorkload
		}

		// 리모트 workload 식별: pod 이름 > pod IP 순서
		remoteID := nodeID(ev.RemoteNs, ev.RemotePod)
		if remoteID == "" {
			if ev.RemoteIp != 0 {
				remoteID = fmt.Sprintf("%d.%d.%d.%d",
					(ev.RemoteIp>>24)&0xff, (ev.RemoteIp>>16)&0xff,
					(ev.RemoteIp>>8)&0xff, ev.RemoteIp&0xff)
			} else {
				continue
			}
		}

		if _, ok := nodeSet[localID]; !ok {
			nodeSet[localID] = topoNode{
				ID:        localID,
				Namespace: ev.Namespace,
				Workload:  localWorkload,
			}
		}
		if _, ok := nodeSet[remoteID]; !ok {
			nodeSet[remoteID] = topoNode{
				ID:        remoteID,
				Namespace: ev.RemoteNs,
				Workload:  aggregator.WorkloadName(ev.RemotePod),
			}
		}

		// 요청 방향 엣지: A→B = A가 B를 호출
		// Direction 0(SEND=응답 송신): 로컬이 서버 → 요청은 리모트(클라이언트)→로컬(서버)
		// Direction 1(RECV=응답 수신): 로컬이 클라이언트 → 요청은 로컬(클라이언트)→리모트(서버)
		var src, dst string
		if ev.Direction == 0 {
			src, dst = remoteID, localID
		} else {
			src, dst = localID, remoteID
		}

		ek := edgeKey{Src: src, Dst: dst}
		ec := edgeMap[ek]
		if ec == nil {
			ec = &edgeCounts{}
			edgeMap[ek] = ec
		}
		ec.total++
		if ev.HttpStatus >= 200 && ev.HttpStatus < 400 {
			ec.success++
		} else if ev.HttpStatus >= 400 {
			ec.error++
		}
		if ev.LatencyNs > 0 {
			ec.latencySum += int64(ev.LatencyNs)
			ec.latencyCount++
		}
	}

	nodes := make([]topoNode, 0, len(nodeSet))
	for _, n := range nodeSet {
		nodes = append(nodes, n)
	}

	edges := make([]topoEdge, 0, len(edgeMap))
	for ek, ec := range edgeMap {
		rate := 0.0
		if ec.total > 0 {
			rate = float64(ec.success) / float64(ec.total) * 100
		}
		avgLatencyMs := 0.0
		if ec.latencyCount > 0 {
			avgLatencyMs = float64(ec.latencySum) / float64(ec.latencyCount) / 1e6
		}
		edges = append(edges, topoEdge{
			ID:           ek.Src + "->" + ek.Dst,
			Source:       ek.Src,
			Target:       ek.Dst,
			Total:        ec.total,
			Success:      ec.success,
			Error:        ec.error,
			SuccessRate:  rate,
			AvgLatencyMs: avgLatencyMs,
		})
	}

	c.JSON(http.StatusOK, topoResponse{Nodes: nodes, Edges: edges})
}

func nodeID(ns, podName string) string {
	workload := aggregator.WorkloadName(podName)
	if ns == "" {
		return workload
	}
	return ns + "/" + workload
}
