package metrics

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gihongjo/nefi/internal/model"
)

// Default configuration values.
const (
	DefaultSlidingWindow = 5 * time.Minute
	DefaultFlushInterval = 30 * time.Second
)

// Predefined latency histogram bucket boundaries in nanoseconds.
// Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s, +Inf
var defaultBucketBoundaries = []float64{
	1e6,   // 1ms
	5e6,   // 5ms
	10e6,  // 10ms
	25e6,  // 25ms
	50e6,  // 50ms
	100e6, // 100ms
	250e6, // 250ms
	500e6, // 500ms
	1e9,   // 1s
	2.5e9, // 2.5s
	5e9,   // 5s
	10e9,  // 10s
}

// Aggregator collects in-memory metrics over a sliding window and
// periodically flushes aggregated time series points to storage.
type Aggregator struct {
	metricWriter model.MetricWriter
	logger       *zap.Logger

	slidingWindow time.Duration
	flushInterval time.Duration
	buckets       []float64

	mu       sync.Mutex
	services map[string]*serviceMetrics

	stopCh chan struct{}
	doneCh chan struct{}
}

// serviceMetrics holds per-service aggregated metrics.
type serviceMetrics struct {
	namespace string

	// Latency histogram: counts per bucket. len == len(buckets)+1
	// (the last element is the +Inf bucket).
	latencyCounts []uint64
	latencySum    float64

	callCount  uint64
	errorCount uint64
	bytesSent  uint64
	bytesRecv  uint64

	// Track when observations were recorded so that we can expire
	// entries outside the sliding window. We use a simple approach:
	// observations are accumulated and reset on each flush cycle.
	lastObserved time.Time
}

// NewAggregator creates a new in-memory metrics aggregator.
func NewAggregator(metricWriter model.MetricWriter, logger *zap.Logger) *Aggregator {
	return &Aggregator{
		metricWriter:  metricWriter,
		logger:        logger.Named("metrics-aggregator"),
		slidingWindow: DefaultSlidingWindow,
		flushInterval: DefaultFlushInterval,
		buckets:       defaultBucketBoundaries,
		services:      make(map[string]*serviceMetrics),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Start begins the background flush loop.
func (a *Aggregator) Start() {
	go a.flushLoop()
}

// Stop signals the flush loop to stop and waits for completion.
func (a *Aggregator) Stop() {
	close(a.stopCh)
	<-a.doneCh
}

// ObserveConnection records an L4 connection event.
func (a *Aggregator) ObserveConnection(ev *model.ConnectionEvent) {
	svc := ev.Source.Service
	if svc == "" {
		svc = ev.Destination.Service
	}
	if svc == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	sm := a.getOrCreate(svc, ev.Source.Namespace)
	sm.callCount++
	sm.bytesSent += ev.BytesSent
	sm.bytesRecv += ev.BytesRecv
	sm.lastObserved = time.Now()

	// Use connection duration as a latency proxy.
	if ev.DurationNs > 0 {
		a.observeLatency(sm, float64(ev.DurationNs))
	}
}

// ObserveHTTPRequest records an L7 HTTP/gRPC request event.
func (a *Aggregator) ObserveHTTPRequest(ev *model.HTTPRequestEvent) {
	svc := ev.Destination.Service
	if svc == "" {
		svc = ev.Source.Service
	}
	if svc == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	sm := a.getOrCreate(svc, ev.Destination.Namespace)
	sm.callCount++
	if ev.StatusCode >= 500 {
		sm.errorCount++
	}
	sm.lastObserved = time.Now()

	if ev.LatencyNs > 0 {
		a.observeLatency(sm, float64(ev.LatencyNs))
	}
}

// getOrCreate returns the serviceMetrics for the given service, creating
// it if necessary. Must be called with a.mu held.
func (a *Aggregator) getOrCreate(service, namespace string) *serviceMetrics {
	sm, ok := a.services[service]
	if !ok {
		sm = &serviceMetrics{
			namespace:     namespace,
			latencyCounts: make([]uint64, len(a.buckets)+1),
		}
		a.services[service] = sm
	}
	return sm
}

// observeLatency records a latency observation into the histogram buckets.
// Must be called with a.mu held.
func (a *Aggregator) observeLatency(sm *serviceMetrics, latencyNs float64) {
	sm.latencySum += latencyNs

	// Find the appropriate bucket.
	inserted := false
	for i, boundary := range a.buckets {
		if latencyNs <= boundary {
			sm.latencyCounts[i]++
			inserted = true
			break
		}
	}
	if !inserted {
		// Falls into +Inf bucket.
		sm.latencyCounts[len(a.buckets)]++
	}
}

// flushLoop runs the periodic flush.
func (a *Aggregator) flushLoop() {
	defer close(a.doneCh)

	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.flush()
		case <-a.stopCh:
			// Final flush before exit.
			a.flush()
			return
		}
	}
}

// flush aggregates the current in-memory metrics into TimeSeriesPoints
// and writes them to storage, then resets the accumulators.
func (a *Aggregator) flush() {
	a.mu.Lock()
	snapshot := a.services
	a.services = make(map[string]*serviceMetrics)
	a.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		latencyPoints []model.TimeSeriesPoint
		callPoints    []model.TimeSeriesPoint
		errorPoints   []model.TimeSeriesPoint
		trafficPoints []model.TimeSeriesPoint
	)

	for svc, sm := range snapshot {
		labels := map[string]string{
			"service":   svc,
			"namespace": sm.namespace,
		}

		// Latency: compute P50, P95, P99 from the histogram.
		totalCount := totalHistogramCount(sm.latencyCounts)
		if totalCount > 0 {
			p50 := histogramPercentile(a.buckets, sm.latencyCounts, totalCount, 0.50)
			p95 := histogramPercentile(a.buckets, sm.latencyCounts, totalCount, 0.95)
			p99 := histogramPercentile(a.buckets, sm.latencyCounts, totalCount, 0.99)

			latencyPoints = append(latencyPoints,
				model.TimeSeriesPoint{
					Timestamp: now,
					Value:     p50,
					Labels:    withLabel(labels, "quantile", "0.5"),
				},
				model.TimeSeriesPoint{
					Timestamp: now,
					Value:     p95,
					Labels:    withLabel(labels, "quantile", "0.95"),
				},
				model.TimeSeriesPoint{
					Timestamp: now,
					Value:     p99,
					Labels:    withLabel(labels, "quantile", "0.99"),
				},
			)
		}

		// Call rate: total calls in the flush interval.
		callPoints = append(callPoints, model.TimeSeriesPoint{
			Timestamp: now,
			Value:     float64(sm.callCount),
			Labels:    copyLabels(labels),
		})

		// Error rate: error count / call count.
		var errorRate float64
		if sm.callCount > 0 {
			errorRate = float64(sm.errorCount) / float64(sm.callCount)
		}
		errorPoints = append(errorPoints, model.TimeSeriesPoint{
			Timestamp: now,
			Value:     errorRate,
			Labels:    copyLabels(labels),
		})

		// Traffic: bytes sent and received.
		trafficPoints = append(trafficPoints,
			model.TimeSeriesPoint{
				Timestamp: now,
				Value:     float64(sm.bytesSent),
				Labels:    withLabel(labels, "direction", "sent"),
			},
			model.TimeSeriesPoint{
				Timestamp: now,
				Value:     float64(sm.bytesRecv),
				Labels:    withLabel(labels, "direction", "recv"),
			},
		)
	}

	// Write each metric type.
	if len(latencyPoints) > 0 {
		if err := a.metricWriter.WriteMetrics(ctx, latencyPoints, "latency"); err != nil {
			a.logger.Error("failed to write latency metrics", zap.Error(err))
		}
	}
	if len(callPoints) > 0 {
		if err := a.metricWriter.WriteMetrics(ctx, callPoints, "call_rate"); err != nil {
			a.logger.Error("failed to write call rate metrics", zap.Error(err))
		}
	}
	if len(errorPoints) > 0 {
		if err := a.metricWriter.WriteMetrics(ctx, errorPoints, "error_rate"); err != nil {
			a.logger.Error("failed to write error rate metrics", zap.Error(err))
		}
	}
	if len(trafficPoints) > 0 {
		if err := a.metricWriter.WriteMetrics(ctx, trafficPoints, "traffic"); err != nil {
			a.logger.Error("failed to write traffic metrics", zap.Error(err))
		}
	}

	a.logger.Debug("flushed metrics",
		zap.Int("services", len(snapshot)),
		zap.Int("latencyPoints", len(latencyPoints)),
		zap.Int("callPoints", len(callPoints)),
		zap.Int("errorPoints", len(errorPoints)),
		zap.Int("trafficPoints", len(trafficPoints)),
	)
}

// -----------------------------------------------------------------------
// Histogram helpers
// -----------------------------------------------------------------------

// totalHistogramCount returns the sum of all bucket counts.
func totalHistogramCount(counts []uint64) uint64 {
	var total uint64
	for _, c := range counts {
		total += c
	}
	return total
}

// histogramPercentile estimates a percentile from the histogram buckets
// using linear interpolation within the target bucket.
//
// buckets:  the upper boundary of each bucket (len N).
// counts:   bucket counts (len N+1; last is +Inf).
// total:    total number of observations.
// quantile: desired quantile in [0,1].
func histogramPercentile(buckets []float64, counts []uint64, total uint64, quantile float64) float64 {
	target := quantile * float64(total)
	var cumulative float64

	for i, count := range counts {
		cumulative += float64(count)
		if cumulative >= target {
			// Determine the bucket boundaries.
			var lower, upper float64
			if i == 0 {
				lower = 0
			} else if i <= len(buckets) {
				lower = buckets[i-1]
			}

			if i < len(buckets) {
				upper = buckets[i]
			} else {
				// +Inf bucket: use 2x the last boundary as an estimate.
				if len(buckets) > 0 {
					upper = buckets[len(buckets)-1] * 2
				}
			}

			// Linear interpolation within the bucket.
			prevCumulative := cumulative - float64(count)
			if count == 0 {
				return lower
			}
			fraction := (target - prevCumulative) / float64(count)
			return lower + fraction*(upper-lower)
		}
	}

	// Should not reach here if total > 0.
	if len(buckets) > 0 {
		return buckets[len(buckets)-1]
	}
	return 0
}

// -----------------------------------------------------------------------
// Label helpers
// -----------------------------------------------------------------------

// copyLabels creates a shallow copy of a label map.
func copyLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// withLabel creates a copy of labels with an additional key-value pair.
func withLabel(src map[string]string, key, value string) map[string]string {
	dst := make(map[string]string, len(src)+1)
	for k, v := range src {
		dst[k] = v
	}
	dst[key] = value
	return dst
}
