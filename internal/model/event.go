package model

import "time"

// Endpoint represents a network endpoint with Kubernetes metadata.
type Endpoint struct {
	IP           string `json:"ip"`
	Port         uint16 `json:"port"`
	Pod          string `json:"pod"`
	Namespace    string `json:"namespace"`
	Workload     string `json:"workload"`
	WorkloadType string `json:"workloadType"`
	Service      string `json:"service"`
}

// ConnectionEvent represents an L4 TCP connection event.
type ConnectionEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Node        string    `json:"node"`
	Source      Endpoint  `json:"source"`
	Destination Endpoint  `json:"destination"`
	BytesSent   uint64    `json:"bytesSent"`
	BytesRecv   uint64    `json:"bytesRecv"`
	DurationNs  uint64    `json:"durationNs"`
	Retransmits uint32    `json:"retransmits"`
	Protocol    string    `json:"protocol"`
}

// HTTPRequestEvent represents an L7 HTTP/gRPC request event.
type HTTPRequestEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Node        string    `json:"node"`
	Source      Endpoint  `json:"source"`
	Destination Endpoint  `json:"destination"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	StatusCode  uint16    `json:"statusCode"`
	LatencyNs   uint64    `json:"latencyNs"`
	Protocol    string    `json:"protocol"`
}

// DependencyLink represents a directed edge between two services.
type DependencyLink struct {
	Parent       string `json:"parent"`
	Child        string `json:"child"`
	CallCount    uint64 `json:"callCount"`
	ErrorCount   uint64 `json:"errorCount"`
	P99LatencyNs uint64 `json:"p99LatencyNs"`
}

// TimeSeriesPoint represents a single metric data point.
type TimeSeriesPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// TopologyNode represents a node in the service topology graph.
type TopologyNode struct {
	ID           string `json:"id"`
	Service      string `json:"service"`
	Namespace    string `json:"namespace"`
	WorkloadType string `json:"workloadType"`
	IsExternal   bool   `json:"isExternal"`
}

// TopologyEdge represents an edge in the service topology graph.
type TopologyEdge struct {
	Source       string  `json:"source"`
	Target       string  `json:"target"`
	CallCount    uint64  `json:"callCount"`
	ErrorCount   uint64  `json:"errorCount"`
	P99LatencyNs uint64  `json:"p99LatencyNs"`
	BytesSent    uint64  `json:"bytesSent"`
	ErrorRate    float64 `json:"errorRate"`
}

// Topology represents the full service topology.
type Topology struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}
