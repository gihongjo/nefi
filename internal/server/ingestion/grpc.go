package ingestion

import (
	"context"
	"io"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/gihongjo/nefi/internal/model"
	"github.com/gihongjo/nefi/internal/server/metrics"
)

// -----------------------------------------------------------------------
// Inline gRPC interface definitions (matching internal/proto/nefi.proto)
// These will be replaced once protoc is run.
// -----------------------------------------------------------------------

// EndpointProto mirrors the proto EndpointProto message.
type EndpointProto struct {
	IP           string `json:"ip"`
	Port         uint32 `json:"port"`
	Pod          string `json:"pod"`
	Namespace    string `json:"namespace"`
	Workload     string `json:"workload"`
	WorkloadType string `json:"workload_type"`
	Service      string `json:"service"`
}

// ConnectionEventProto mirrors the proto ConnectionEvent message.
type ConnectionEventProto struct {
	TimestampNs int64          `json:"timestamp_ns"`
	Node        string         `json:"node"`
	Source      *EndpointProto `json:"source"`
	Destination *EndpointProto `json:"destination"`
	BytesSent   uint64         `json:"bytes_sent"`
	BytesRecv   uint64         `json:"bytes_recv"`
	DurationNs  uint64         `json:"duration_ns"`
	Retransmits uint32         `json:"retransmits"`
	Protocol    string         `json:"protocol"`
}

// HTTPRequestEventProto mirrors the proto HTTPRequestEvent message.
type HTTPRequestEventProto struct {
	TimestampNs int64          `json:"timestamp_ns"`
	Node        string         `json:"node"`
	Source      *EndpointProto `json:"source"`
	Destination *EndpointProto `json:"destination"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	StatusCode  uint32         `json:"status_code"`
	LatencyNs   uint64         `json:"latency_ns"`
	Protocol    string         `json:"protocol"`
}

// EventBatch mirrors the proto EventBatch message.
type EventBatch struct {
	Node         string                  `json:"node"`
	Connections  []ConnectionEventProto  `json:"connections"`
	HTTPRequests []HTTPRequestEventProto `json:"http_requests"`
}

// StreamResponse mirrors the proto StreamResponse message.
type StreamResponse struct {
	Accepted uint64 `json:"accepted"`
	Error    string `json:"error"`
}

// EventIngestionServer defines the gRPC server interface for event ingestion.
// This matches the EventIngestion service in nefi.proto:
//
//	service EventIngestion {
//	    rpc StreamEvents(stream EventBatch) returns (StreamResponse);
//	}
type EventIngestionServer interface {
	StreamEvents(stream EventIngestion_StreamEventsServer) error
}

// EventIngestion_StreamEventsServer is the server-side stream interface
// for the StreamEvents RPC.
type EventIngestion_StreamEventsServer interface {
	SendAndClose(*StreamResponse) error
	Recv() (*EventBatch, error)
	grpc.ServerStream
}

// RegisterEventIngestionServer registers the ingestion server on a gRPC server.
func RegisterEventIngestionServer(s *grpc.Server, srv EventIngestionServer) {
	s.RegisterService(&_EventIngestion_serviceDesc, srv)
}

var _EventIngestion_serviceDesc = grpc.ServiceDesc{
	ServiceName: "nefi.EventIngestion",
	HandlerType: (*EventIngestionServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamEvents",
			Handler:       _EventIngestion_StreamEvents_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "nefi.proto",
}

func _EventIngestion_StreamEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(EventIngestionServer).StreamEvents(&streamEventsServer{stream})
}

type streamEventsServer struct {
	grpc.ServerStream
}

func (s *streamEventsServer) SendAndClose(resp *StreamResponse) error {
	return s.ServerStream.SendMsg(resp)
}

func (s *streamEventsServer) Recv() (*EventBatch, error) {
	batch := new(EventBatch)
	if err := s.ServerStream.RecvMsg(batch); err != nil {
		return nil, err
	}
	return batch, nil
}

// -----------------------------------------------------------------------
// IngestionServer implements EventIngestionServer.
// -----------------------------------------------------------------------

// IngestionServer receives event batches from agents via gRPC,
// converts proto types to model types, and fans out to the storage
// writer and metrics aggregator.
type IngestionServer struct {
	writer     model.EventWriter
	aggregator *metrics.Aggregator
	logger     *zap.Logger
	accepted   atomic.Uint64
}

// NewIngestionServer creates a new IngestionServer.
func NewIngestionServer(writer model.EventWriter, aggregator *metrics.Aggregator, logger *zap.Logger) *IngestionServer {
	return &IngestionServer{
		writer:     writer,
		aggregator: aggregator,
		logger:     logger.Named("ingestion"),
	}
}

// StreamEvents implements EventIngestionServer. It receives a client-side
// stream of EventBatch messages, decodes them to model types, and fans
// out to the storage writer and metrics aggregator.
func (s *IngestionServer) StreamEvents(stream EventIngestion_StreamEventsServer) error {
	var totalAccepted uint64

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			s.logger.Info("stream finished",
				zap.Uint64("totalAccepted", totalAccepted),
			)
			return stream.SendAndClose(&StreamResponse{
				Accepted: totalAccepted,
			})
		}
		if err != nil {
			s.logger.Error("failed to receive batch", zap.Error(err))
			return err
		}

		accepted, processErr := s.processBatch(stream.Context(), batch)
		totalAccepted += accepted
		if processErr != nil {
			s.logger.Error("failed to process batch",
				zap.String("node", batch.Node),
				zap.Error(processErr),
			)
			// Continue receiving; do not abort the stream on transient errors.
		} else {
			s.logger.Debug("processed batch",
				zap.String("node", batch.Node),
				zap.Int("connections", len(batch.Connections)),
				zap.Int("httpRequests", len(batch.HTTPRequests)),
			)
		}
	}
}

// processBatch converts a proto EventBatch to model types and writes
// them to storage and the metrics aggregator. Returns the number of
// events accepted and any error.
func (s *IngestionServer) processBatch(ctx context.Context, batch *EventBatch) (uint64, error) {
	var accepted uint64

	// Convert and write connection events.
	if len(batch.Connections) > 0 {
		conns := make([]model.ConnectionEvent, 0, len(batch.Connections))
		for _, c := range batch.Connections {
			conns = append(conns, protoToConnectionEvent(&c, batch.Node))
		}

		if err := s.writer.WriteConnectionEvents(ctx, conns); err != nil {
			return accepted, err
		}

		// Fan out to aggregator.
		for i := range conns {
			s.aggregator.ObserveConnection(&conns[i])
		}

		accepted += uint64(len(conns))
	}

	// Convert and write HTTP request events.
	if len(batch.HTTPRequests) > 0 {
		reqs := make([]model.HTTPRequestEvent, 0, len(batch.HTTPRequests))
		for _, r := range batch.HTTPRequests {
			reqs = append(reqs, protoToHTTPRequestEvent(&r, batch.Node))
		}

		if err := s.writer.WriteHTTPRequestEvents(ctx, reqs); err != nil {
			return accepted, err
		}

		// Fan out to aggregator.
		for i := range reqs {
			s.aggregator.ObserveHTTPRequest(&reqs[i])
		}

		accepted += uint64(len(reqs))
	}

	s.accepted.Add(accepted)
	return accepted, nil
}

// TotalAccepted returns the cumulative count of accepted events.
func (s *IngestionServer) TotalAccepted() uint64 {
	return s.accepted.Load()
}

// -----------------------------------------------------------------------
// Proto → Model conversion helpers
// -----------------------------------------------------------------------

func protoToEndpoint(ep *EndpointProto) model.Endpoint {
	if ep == nil {
		return model.Endpoint{}
	}
	return model.Endpoint{
		IP:           ep.IP,
		Port:         uint16(ep.Port),
		Pod:          ep.Pod,
		Namespace:    ep.Namespace,
		Workload:     ep.Workload,
		WorkloadType: ep.WorkloadType,
		Service:      ep.Service,
	}
}

func protoToConnectionEvent(c *ConnectionEventProto, node string) model.ConnectionEvent {
	n := c.Node
	if n == "" {
		n = node
	}
	return model.ConnectionEvent{
		Timestamp:   time.Unix(0, c.TimestampNs),
		Node:        n,
		Source:      protoToEndpoint(c.Source),
		Destination: protoToEndpoint(c.Destination),
		BytesSent:   c.BytesSent,
		BytesRecv:   c.BytesRecv,
		DurationNs:  c.DurationNs,
		Retransmits: c.Retransmits,
		Protocol:    c.Protocol,
	}
}

func protoToHTTPRequestEvent(r *HTTPRequestEventProto, node string) model.HTTPRequestEvent {
	n := r.Node
	if n == "" {
		n = node
	}
	return model.HTTPRequestEvent{
		Timestamp:   time.Unix(0, r.TimestampNs),
		Node:        n,
		Source:      protoToEndpoint(r.Source),
		Destination: protoToEndpoint(r.Destination),
		Method:      r.Method,
		Path:        r.Path,
		StatusCode:  uint16(r.StatusCode),
		LatencyNs:   r.LatencyNs,
		Protocol:    r.Protocol,
	}
}
