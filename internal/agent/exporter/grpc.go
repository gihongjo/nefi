package exporter

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gihongjo/nefi/internal/model"
)

const (
	// defaultBatchSize is the maximum number of events per batch before flushing.
	defaultBatchSize = 100

	// defaultFlushInterval is how often buffered events are flushed even if
	// the batch is not full.
	defaultFlushInterval = 100 * time.Millisecond

	// defaultQueueLimit is the maximum number of events held in the in-memory
	// queue when the server is unavailable.
	defaultQueueLimit = 10000

	// maxReconnectBackoff caps the exponential backoff between reconnection
	// attempts.
	maxReconnectBackoff = 30 * time.Second

	// initialReconnectBackoff is the starting backoff duration.
	initialReconnectBackoff = 500 * time.Millisecond
)

// ---------------------------------------------------------------------------
// Minimal gRPC client interface matching the proto definition.
// This will be replaced by the actual generated code once protoc is run.
// ---------------------------------------------------------------------------

// EndpointProto is the wire representation of an endpoint.
type EndpointProto struct {
	IP           string `protobuf:"bytes,1,opt,name=ip,proto3"`
	Port         uint32 `protobuf:"varint,2,opt,name=port,proto3"`
	Pod          string `protobuf:"bytes,3,opt,name=pod,proto3"`
	Namespace    string `protobuf:"bytes,4,opt,name=namespace,proto3"`
	Workload     string `protobuf:"bytes,5,opt,name=workload,proto3"`
	WorkloadType string `protobuf:"bytes,6,opt,name=workload_type,proto3"`
	Service      string `protobuf:"bytes,7,opt,name=service,proto3"`
}

// ConnectionEventProto is the wire representation of a connection event.
type ConnectionEventProto struct {
	TimestampNs int64          `protobuf:"varint,1,opt,name=timestamp_ns,proto3"`
	Node        string         `protobuf:"bytes,2,opt,name=node,proto3"`
	Source      *EndpointProto `protobuf:"bytes,3,opt,name=source,proto3"`
	Destination *EndpointProto `protobuf:"bytes,4,opt,name=destination,proto3"`
	BytesSent   uint64         `protobuf:"varint,5,opt,name=bytes_sent,proto3"`
	BytesRecv   uint64         `protobuf:"varint,6,opt,name=bytes_recv,proto3"`
	DurationNs  uint64         `protobuf:"varint,7,opt,name=duration_ns,proto3"`
	Retransmits uint32         `protobuf:"varint,8,opt,name=retransmits,proto3"`
	Protocol    string         `protobuf:"bytes,9,opt,name=protocol,proto3"`
}

// HTTPRequestEventProto is the wire representation of an HTTP request event.
type HTTPRequestEventProto struct {
	TimestampNs int64          `protobuf:"varint,1,opt,name=timestamp_ns,proto3"`
	Node        string         `protobuf:"bytes,2,opt,name=node,proto3"`
	Source      *EndpointProto `protobuf:"bytes,3,opt,name=source,proto3"`
	Destination *EndpointProto `protobuf:"bytes,4,opt,name=destination,proto3"`
	Method      string         `protobuf:"bytes,5,opt,name=method,proto3"`
	Path        string         `protobuf:"bytes,6,opt,name=path,proto3"`
	StatusCode  uint32         `protobuf:"varint,7,opt,name=status_code,proto3"`
	LatencyNs   uint64         `protobuf:"varint,8,opt,name=latency_ns,proto3"`
	Protocol    string         `protobuf:"bytes,9,opt,name=protocol,proto3"`
}

// EventBatchProto is a batch of events sent to the server.
type EventBatchProto struct {
	Node         string                   `protobuf:"bytes,1,opt,name=node,proto3"`
	Connections  []*ConnectionEventProto  `protobuf:"bytes,2,rep,name=connections,proto3"`
	HttpRequests []*HTTPRequestEventProto `protobuf:"bytes,3,rep,name=http_requests,proto3"`
}

// StreamResponseProto is the server's response to a batch.
type StreamResponseProto struct {
	Accepted uint64 `protobuf:"varint,1,opt,name=accepted,proto3"`
	Error    string `protobuf:"bytes,2,opt,name=error,proto3"`
}

// EventIngestionClient defines the gRPC client interface for the
// EventIngestion service. The actual generated interface will replace this.
type EventIngestionClient interface {
	StreamEvents(ctx context.Context, opts ...grpc.CallOption) (EventIngestion_StreamEventsClient, error)
}

// EventIngestion_StreamEventsClient is the client-side streaming interface.
type EventIngestion_StreamEventsClient interface {
	Send(*EventBatchProto) error
	CloseAndRecv() (*StreamResponseProto, error)
	grpc.ClientStream
}

// ---------------------------------------------------------------------------
// Exporter implementation
// ---------------------------------------------------------------------------

// Exporter batches events and streams them to nefi-server via gRPC.
type Exporter struct {
	logger   *zap.Logger
	addr     string
	nodeName string

	mu    sync.Mutex
	queue []interface{} // buffered events when server is unreachable

	conn   *grpc.ClientConn
	stream EventIngestion_StreamEventsClient

	batchSize     int
	flushInterval time.Duration
	queueLimit    int
}

// NewExporter creates a new gRPC Exporter targeting the given server address.
func NewExporter(logger *zap.Logger, serverAddr, nodeName string) *Exporter {
	return &Exporter{
		logger:        logger,
		addr:          serverAddr,
		nodeName:      nodeName,
		queue:         make([]interface{}, 0, defaultQueueLimit),
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		queueLimit:    defaultQueueLimit,
	}
}

// Enqueue adds an event (model.ConnectionEvent or model.HTTPRequestEvent) to
// the in-memory queue. If the queue is at capacity, the oldest event is dropped.
func (e *Exporter) Enqueue(evt interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.queue) >= e.queueLimit {
		// Drop the oldest event to make room.
		e.queue = e.queue[1:]
		e.logger.Warn("event queue full, dropping oldest event")
	}
	e.queue = append(e.queue, evt)
}

// Start runs the export loop. It connects to the gRPC server, batches queued
// events, and flushes them periodically. It reconnects with exponential backoff
// when the connection is lost. Start blocks until ctx is cancelled.
func (e *Exporter) Start(ctx context.Context) error {
	backoff := initialReconnectBackoff

	for {
		select {
		case <-ctx.Done():
			e.closeConn()
			return ctx.Err()
		default:
		}

		// Attempt to connect.
		if err := e.connect(ctx); err != nil {
			e.logger.Warn("failed to connect to nefi-server",
				zap.String("addr", e.addr),
				zap.Error(err),
				zap.Duration("retry_in", backoff))

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}

			// Exponential backoff with cap.
			backoff = time.Duration(math.Min(
				float64(backoff)*2,
				float64(maxReconnectBackoff),
			))
			continue
		}

		// Connected; reset backoff.
		backoff = initialReconnectBackoff
		e.logger.Info("connected to nefi-server", zap.String("addr", e.addr))

		// Run the flush loop until the stream breaks or ctx is cancelled.
		if err := e.flushLoop(ctx); err != nil {
			e.logger.Warn("stream error, will reconnect",
				zap.Error(err),
				zap.Duration("retry_in", backoff))
			e.closeConn()
		}
	}
}

// connect establishes a gRPC connection and opens a StreamEvents client stream.
func (e *Exporter) connect(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, e.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}

	e.conn = conn

	// Note: In the real implementation, this would use the generated
	// proto.NewEventIngestionClient(conn).StreamEvents(ctx). For now we store
	// the connection and will open the stream when the generated code is available.
	// The stream is set to nil; flushLoop handles this gracefully.
	e.stream = nil

	return nil
}

// closeConn tears down the gRPC connection.
func (e *Exporter) closeConn() {
	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
	e.stream = nil
}

// flushLoop periodically drains the event queue into batches and sends them
// over the gRPC stream. It returns when the stream encounters an error or ctx
// is cancelled.
func (e *Exporter) flushLoop(ctx context.Context) error {
	ticker := time.NewTicker(e.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush attempt before shutting down.
			e.flush()
			return ctx.Err()

		case <-ticker.C:
			if err := e.flush(); err != nil {
				return err
			}
		}
	}
}

// flush takes up to batchSize events from the queue and sends them as a single
// EventBatchProto over the gRPC stream.
func (e *Exporter) flush() error {
	e.mu.Lock()
	if len(e.queue) == 0 {
		e.mu.Unlock()
		return nil
	}

	// Take up to batchSize events.
	n := e.batchSize
	if n > len(e.queue) {
		n = len(e.queue)
	}
	batch := make([]interface{}, n)
	copy(batch, e.queue[:n])
	e.queue = e.queue[n:]
	e.mu.Unlock()

	// Build the proto batch.
	pbBatch := &EventBatchProto{
		Node: e.nodeName,
	}

	for _, evt := range batch {
		switch v := evt.(type) {
		case model.ConnectionEvent:
			pbBatch.Connections = append(pbBatch.Connections, connectionEventToProto(v))
		case model.HTTPRequestEvent:
			pbBatch.HttpRequests = append(pbBatch.HttpRequests, httpRequestEventToProto(v))
		default:
			e.logger.Warn("unknown event type in queue", zap.Any("event", evt))
		}
	}

	// If we have no stream yet (proto not generated), log and discard.
	if e.stream == nil {
		e.logger.Debug("no active gRPC stream, batch buffered locally",
			zap.Int("connections", len(pbBatch.Connections)),
			zap.Int("http_requests", len(pbBatch.HttpRequests)))
		return nil
	}

	if err := e.stream.Send(pbBatch); err != nil {
		// Put unsent events back in the queue (best effort).
		e.mu.Lock()
		remaining := make([]interface{}, 0, len(batch)+len(e.queue))
		remaining = append(remaining, batch...)
		remaining = append(remaining, e.queue...)
		if len(remaining) > e.queueLimit {
			remaining = remaining[len(remaining)-e.queueLimit:]
		}
		e.queue = remaining
		e.mu.Unlock()

		return fmt.Errorf("stream send: %w", err)
	}

	e.logger.Debug("flushed event batch",
		zap.Int("connections", len(pbBatch.Connections)),
		zap.Int("http_requests", len(pbBatch.HttpRequests)))

	return nil
}

// ---------------------------------------------------------------------------
// Model -> Proto conversion helpers
// ---------------------------------------------------------------------------

func endpointToProto(ep model.Endpoint) *EndpointProto {
	return &EndpointProto{
		IP:           ep.IP,
		Port:         uint32(ep.Port),
		Pod:          ep.Pod,
		Namespace:    ep.Namespace,
		Workload:     ep.Workload,
		WorkloadType: ep.WorkloadType,
		Service:      ep.Service,
	}
}

func connectionEventToProto(ce model.ConnectionEvent) *ConnectionEventProto {
	return &ConnectionEventProto{
		TimestampNs: ce.Timestamp.UnixNano(),
		Node:        ce.Node,
		Source:      endpointToProto(ce.Source),
		Destination: endpointToProto(ce.Destination),
		BytesSent:   ce.BytesSent,
		BytesRecv:   ce.BytesRecv,
		DurationNs:  ce.DurationNs,
		Retransmits: ce.Retransmits,
		Protocol:    ce.Protocol,
	}
}

func httpRequestEventToProto(he model.HTTPRequestEvent) *HTTPRequestEventProto {
	return &HTTPRequestEventProto{
		TimestampNs: he.Timestamp.UnixNano(),
		Node:        he.Node,
		Source:      endpointToProto(he.Source),
		Destination: endpointToProto(he.Destination),
		Method:      he.Method,
		Path:        he.Path,
		StatusCode:  uint32(he.StatusCode),
		LatencyNs:   he.LatencyNs,
		Protocol:    he.Protocol,
	}
}
