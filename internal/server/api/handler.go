package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/gihongjo/nefi/internal/model"
)

// Handler serves the nefi REST API and WebSocket endpoints.
type Handler struct {
	eventReader   model.EventReader
	depReader     model.DependencyReader
	metricReader  model.MetricReader
	serviceReader model.ServiceReader
	logger        *zap.Logger

	router   *mux.Router
	upgrader websocket.Upgrader

	// WebSocket topology broadcast.
	wsMu      sync.Mutex
	wsClients map[*websocket.Conn]struct{}
	wsStopCh  chan struct{}
	wsDoneCh  chan struct{}
}

// NewHandler creates a new API handler with all routes registered.
func NewHandler(
	eventReader model.EventReader,
	depReader model.DependencyReader,
	metricReader model.MetricReader,
	serviceReader model.ServiceReader,
	logger *zap.Logger,
) *Handler {
	h := &Handler{
		eventReader:   eventReader,
		depReader:     depReader,
		metricReader:  metricReader,
		serviceReader: serviceReader,
		logger:        logger.Named("api"),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		wsClients: make(map[*websocket.Conn]struct{}),
		wsStopCh:  make(chan struct{}),
		wsDoneCh:  make(chan struct{}),
	}

	h.router = mux.NewRouter()
	h.registerRoutes()

	return h
}

// Router returns the configured HTTP router.
func (h *Handler) Router() http.Handler {
	return corsMiddleware(h.router)
}

// StartTopologyBroadcast begins the periodic WebSocket topology broadcast.
func (h *Handler) StartTopologyBroadcast() {
	go h.topologyBroadcastLoop()
}

// StopTopologyBroadcast stops the broadcast loop and closes all WebSocket
// connections.
func (h *Handler) StopTopologyBroadcast() {
	close(h.wsStopCh)
	<-h.wsDoneCh

	h.wsMu.Lock()
	for conn := range h.wsClients {
		conn.Close()
	}
	h.wsClients = make(map[*websocket.Conn]struct{})
	h.wsMu.Unlock()
}

// -----------------------------------------------------------------------
// Route registration
// -----------------------------------------------------------------------

func (h *Handler) registerRoutes() {
	api := h.router.PathPrefix("/api/v1").Subrouter()

	api.HandleFunc("/services", h.handleGetServices).Methods("GET")
	api.HandleFunc("/dependencies", h.handleGetDependencies).Methods("GET")
	api.HandleFunc("/topology", h.handleGetTopology).Methods("GET")
	api.HandleFunc("/metrics/latencies", h.handleGetLatencies).Methods("GET")
	api.HandleFunc("/metrics/calls", h.handleGetCallRates).Methods("GET")
	api.HandleFunc("/metrics/errors", h.handleGetErrorRates).Methods("GET")
	api.HandleFunc("/metrics/traffic", h.handleGetTraffic).Methods("GET")
	api.HandleFunc("/connections", h.handleFindConnections).Methods("GET")
	api.HandleFunc("/requests", h.handleFindRequests).Methods("GET")
	api.HandleFunc("/ws/topology", h.handleWSTopology)

	h.router.HandleFunc("/healthz", h.handleHealth).Methods("GET")
}

// -----------------------------------------------------------------------
// Health endpoint
// -----------------------------------------------------------------------

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// -----------------------------------------------------------------------
// Service endpoints
// -----------------------------------------------------------------------

func (h *Handler) handleGetServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	services, err := h.serviceReader.GetServices(ctx)
	if err != nil {
		h.logger.Error("failed to get services", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get services")
		return
	}
	writeJSON(w, http.StatusOK, services)
}

// -----------------------------------------------------------------------
// Dependency endpoints
// -----------------------------------------------------------------------

func (h *Handler) handleGetDependencies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := model.DependencyQuery{
		StartTime: parseTimeParam(r, "start"),
		EndTime:   parseTimeParam(r, "end"),
		Service:   r.URL.Query().Get("service"),
	}

	deps, err := h.depReader.GetDependencies(ctx, query)
	if err != nil {
		h.logger.Error("failed to get dependencies", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get dependencies")
		return
	}
	writeJSON(w, http.StatusOK, deps)
}

// -----------------------------------------------------------------------
// Topology endpoint
// -----------------------------------------------------------------------

func (h *Handler) handleGetTopology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	topology, err := h.buildTopology(ctx)
	if err != nil {
		h.logger.Error("failed to build topology", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to build topology")
		return
	}
	writeJSON(w, http.StatusOK, topology)
}

func (h *Handler) buildTopology(ctx context.Context) (*model.Topology, error) {
	// Default to the last hour.
	now := time.Now()
	query := model.DependencyQuery{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	}

	deps, err := h.depReader.GetDependencies(ctx, query)
	if err != nil {
		return nil, err
	}

	services, err := h.serviceReader.GetServices(ctx)
	if err != nil {
		return nil, err
	}

	// Build node set from services.
	nodeSet := make(map[string]model.TopologyNode)
	for _, svc := range services {
		nodeSet[svc] = model.TopologyNode{
			ID:      svc,
			Service: svc,
		}
	}

	// Build edges from dependencies and ensure nodes exist for all
	// referenced services.
	edges := make([]model.TopologyEdge, 0, len(deps))
	for _, dep := range deps {
		if _, ok := nodeSet[dep.Parent]; !ok {
			nodeSet[dep.Parent] = model.TopologyNode{
				ID:         dep.Parent,
				Service:    dep.Parent,
				IsExternal: true,
			}
		}
		if _, ok := nodeSet[dep.Child]; !ok {
			nodeSet[dep.Child] = model.TopologyNode{
				ID:         dep.Child,
				Service:    dep.Child,
				IsExternal: true,
			}
		}

		var errorRate float64
		if dep.CallCount > 0 {
			errorRate = float64(dep.ErrorCount) / float64(dep.CallCount)
		}

		edges = append(edges, model.TopologyEdge{
			Source:       dep.Parent,
			Target:       dep.Child,
			CallCount:    dep.CallCount,
			ErrorCount:   dep.ErrorCount,
			P99LatencyNs: dep.P99LatencyNs,
			ErrorRate:    errorRate,
		})
	}

	nodes := make([]model.TopologyNode, 0, len(nodeSet))
	for _, node := range nodeSet {
		nodes = append(nodes, node)
	}

	return &model.Topology{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// -----------------------------------------------------------------------
// Metric endpoints
// -----------------------------------------------------------------------

func (h *Handler) handleGetLatencies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := parseMetricQuery(r)

	points, err := h.metricReader.GetLatencies(ctx, query)
	if err != nil {
		h.logger.Error("failed to get latencies", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get latencies")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (h *Handler) handleGetCallRates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := parseMetricQuery(r)

	points, err := h.metricReader.GetCallRates(ctx, query)
	if err != nil {
		h.logger.Error("failed to get call rates", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get call rates")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (h *Handler) handleGetErrorRates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := parseMetricQuery(r)

	points, err := h.metricReader.GetErrorRates(ctx, query)
	if err != nil {
		h.logger.Error("failed to get error rates", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get error rates")
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (h *Handler) handleGetTraffic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := parseEventQuery(r)

	conns, err := h.eventReader.FindConnections(ctx, query)
	if err != nil {
		h.logger.Error("failed to get traffic data", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get traffic data")
		return
	}

	type trafficSummary struct {
		Service   string `json:"service"`
		BytesSent uint64 `json:"bytesSent"`
		BytesRecv uint64 `json:"bytesRecv"`
	}

	// Aggregate bytes per service.
	svcTraffic := make(map[string]*trafficSummary)
	for _, c := range conns {
		svc := c.Source.Service
		if svc == "" {
			svc = c.Destination.Service
		}
		if svc == "" {
			continue
		}
		t, ok := svcTraffic[svc]
		if !ok {
			t = &trafficSummary{Service: svc}
			svcTraffic[svc] = t
		}
		t.BytesSent += c.BytesSent
		t.BytesRecv += c.BytesRecv
	}

	result := make([]trafficSummary, 0, len(svcTraffic))
	for _, t := range svcTraffic {
		result = append(result, *t)
	}
	writeJSON(w, http.StatusOK, result)
}

// -----------------------------------------------------------------------
// Event query endpoints
// -----------------------------------------------------------------------

func (h *Handler) handleFindConnections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := parseEventQuery(r)

	conns, err := h.eventReader.FindConnections(ctx, query)
	if err != nil {
		h.logger.Error("failed to find connections", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to find connections")
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

func (h *Handler) handleFindRequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := parseEventQuery(r)

	reqs, err := h.eventReader.FindRequests(ctx, query)
	if err != nil {
		h.logger.Error("failed to find requests", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to find requests")
		return
	}
	writeJSON(w, http.StatusOK, reqs)
}

// -----------------------------------------------------------------------
// WebSocket topology
// -----------------------------------------------------------------------

func (h *Handler) handleWSTopology(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("websocket upgrade failed", zap.Error(err))
		return
	}

	h.wsMu.Lock()
	h.wsClients[conn] = struct{}{}
	h.wsMu.Unlock()

	h.logger.Info("websocket client connected",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
	)

	// Keep the connection alive by reading (and discarding) messages.
	// The client is expected to send pings; we close on error.
	go func() {
		defer func() {
			h.wsMu.Lock()
			delete(h.wsClients, conn)
			h.wsMu.Unlock()
			conn.Close()
			h.logger.Info("websocket client disconnected",
				zap.String("remoteAddr", conn.RemoteAddr().String()),
			)
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

func (h *Handler) topologyBroadcastLoop() {
	defer close(h.wsDoneCh)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.broadcastTopology()
		case <-h.wsStopCh:
			return
		}
	}
}

func (h *Handler) broadcastTopology() {
	h.wsMu.Lock()
	clients := make([]*websocket.Conn, 0, len(h.wsClients))
	for conn := range h.wsClients {
		clients = append(clients, conn)
	}
	h.wsMu.Unlock()

	if len(clients) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	topology, err := h.buildTopology(ctx)
	if err != nil {
		h.logger.Error("failed to build topology for broadcast", zap.Error(err))
		return
	}

	data, err := json.Marshal(topology)
	if err != nil {
		h.logger.Error("failed to marshal topology", zap.Error(err))
		return
	}

	for _, conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			h.logger.Debug("failed to write to websocket client",
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.Error(err),
			)
			h.wsMu.Lock()
			delete(h.wsClients, conn)
			h.wsMu.Unlock()
			conn.Close()
		}
	}
}

// -----------------------------------------------------------------------
// Query parameter parsing helpers
// -----------------------------------------------------------------------

func parseTimeParam(r *http.Request, key string) time.Time {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return time.Time{}
	}

	// Try RFC3339 first.
	t, err := time.Parse(time.RFC3339, raw)
	if err == nil {
		return t
	}

	// Try Unix timestamp (seconds).
	sec, err := strconv.ParseInt(raw, 10, 64)
	if err == nil {
		return time.Unix(sec, 0)
	}

	// Try Unix timestamp (milliseconds).
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err == nil {
		return time.UnixMilli(ms)
	}

	return time.Time{}
}

func parseIntParam(r *http.Request, key string, defaultVal int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(raw)
	if err != nil || val <= 0 {
		return defaultVal
	}
	return val
}

func parseEventQuery(r *http.Request) model.EventQuery {
	return model.EventQuery{
		Service:   r.URL.Query().Get("service"),
		Namespace: r.URL.Query().Get("namespace"),
		StartTime: parseTimeParam(r, "start"),
		EndTime:   parseTimeParam(r, "end"),
		Limit:     parseIntParam(r, "limit", 100),
	}
}

func parseMetricQuery(r *http.Request) model.MetricQuery {
	return model.MetricQuery{
		Service:   r.URL.Query().Get("service"),
		Namespace: r.URL.Query().Get("namespace"),
		StartTime: parseTimeParam(r, "start"),
		EndTime:   parseTimeParam(r, "end"),
		Step:      r.URL.Query().Get("step"),
	}
}

// -----------------------------------------------------------------------
// JSON response helpers
// -----------------------------------------------------------------------

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Best-effort; headers are already sent.
		_ = err
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

// -----------------------------------------------------------------------
// CORS middleware
// -----------------------------------------------------------------------

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
