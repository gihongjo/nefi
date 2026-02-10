package model

import "context"

// EventWriter writes events to storage.
type EventWriter interface {
	WriteConnectionEvents(ctx context.Context, events []ConnectionEvent) error
	WriteHTTPRequestEvents(ctx context.Context, events []HTTPRequestEvent) error
}

// EventReader reads events from storage.
type EventReader interface {
	FindConnections(ctx context.Context, query EventQuery) ([]ConnectionEvent, error)
	FindRequests(ctx context.Context, query EventQuery) ([]HTTPRequestEvent, error)
}

// DependencyReader reads dependency links.
type DependencyReader interface {
	GetDependencies(ctx context.Context, query DependencyQuery) ([]DependencyLink, error)
}

// DependencyWriter writes dependency links.
type DependencyWriter interface {
	WriteDependencies(ctx context.Context, deps []DependencyLink) error
}

// MetricReader reads aggregated metrics.
type MetricReader interface {
	GetLatencies(ctx context.Context, params MetricQuery) ([]TimeSeriesPoint, error)
	GetCallRates(ctx context.Context, params MetricQuery) ([]TimeSeriesPoint, error)
	GetErrorRates(ctx context.Context, params MetricQuery) ([]TimeSeriesPoint, error)
}

// MetricWriter writes aggregated metrics.
type MetricWriter interface {
	WriteMetrics(ctx context.Context, points []TimeSeriesPoint, metricType string) error
}

// ServiceReader reads service metadata.
type ServiceReader interface {
	GetServices(ctx context.Context) ([]string, error)
	GetOperations(ctx context.Context, service string) ([]string, error)
}
