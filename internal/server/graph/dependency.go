package graph

import (
	"context"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gihongjo/nefi/internal/model"
)

// DependencyComputer periodically reads recent connection and HTTP request
// events from storage, computes directed dependency links between services,
// and writes the result back to storage.
type DependencyComputer struct {
	eventReader model.EventReader
	depWriter   model.DependencyWriter
	logger      *zap.Logger

	interval time.Duration
	window   time.Duration

	mu   sync.Mutex
	deps map[string]*linkAccumulator // key: "parent->child"

	stopCh chan struct{}
	doneCh chan struct{}
}

// linkAccumulator accumulates call counts, error counts, and latency
// samples for a single parent->child dependency edge.
type linkAccumulator struct {
	parent     string
	child      string
	callCount  uint64
	errorCount uint64
	latencies  []uint64 // stored as nanoseconds for P99 computation
}

// NewDependencyComputer creates a new DependencyComputer.
//
//   - eventReader: provides access to recent connection and HTTP events.
//   - depWriter:   persists computed dependency links.
//   - logger:      structured logger.
func NewDependencyComputer(eventReader model.EventReader, depWriter model.DependencyWriter, logger *zap.Logger) *DependencyComputer {
	return &DependencyComputer{
		eventReader: eventReader,
		depWriter:   depWriter,
		logger:      logger.Named("dependency-computer"),
		interval:    30 * time.Second,
		window:      5 * time.Minute,
		deps:        make(map[string]*linkAccumulator),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

// Start begins the periodic dependency computation loop.
func (dc *DependencyComputer) Start() {
	go dc.run()
}

// Stop signals the computation loop to stop and waits for it to finish.
func (dc *DependencyComputer) Stop() {
	close(dc.stopCh)
	<-dc.doneCh
}

func (dc *DependencyComputer) run() {
	defer close(dc.doneCh)

	// Run once immediately on start.
	dc.compute()

	ticker := time.NewTicker(dc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dc.compute()
		case <-dc.stopCh:
			return
		}
	}
}

// compute reads recent events, builds dependency links, and writes them
// to storage.
func (dc *DependencyComputer) compute() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now()
	query := model.EventQuery{
		StartTime: now.Add(-dc.window),
		EndTime:   now,
		Limit:     50000,
	}

	dc.mu.Lock()
	// Reset accumulators each cycle.
	dc.deps = make(map[string]*linkAccumulator)
	dc.mu.Unlock()

	// Read connection events.
	conns, err := dc.eventReader.FindConnections(ctx, query)
	if err != nil {
		dc.logger.Error("failed to read connection events", zap.Error(err))
	} else {
		for i := range conns {
			dc.addConnectionEvent(&conns[i])
		}
	}

	// Read HTTP request events.
	reqs, err := dc.eventReader.FindRequests(ctx, query)
	if err != nil {
		dc.logger.Error("failed to read HTTP request events", zap.Error(err))
	} else {
		for i := range reqs {
			dc.addHTTPRequestEvent(&reqs[i])
		}
	}

	// Compute final links and write.
	links := dc.buildLinks()
	if len(links) == 0 {
		dc.logger.Debug("no dependency links computed")
		return
	}

	if err := dc.depWriter.WriteDependencies(ctx, links); err != nil {
		dc.logger.Error("failed to write dependencies", zap.Error(err))
		return
	}

	dc.logger.Info("computed and wrote dependency links",
		zap.Int("count", len(links)),
	)
}

// addConnectionEvent records a connection event in the accumulator.
func (dc *DependencyComputer) addConnectionEvent(ev *model.ConnectionEvent) {
	src := ev.Source.Service
	dst := ev.Destination.Service
	if src == "" || dst == "" || src == dst {
		return
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	key := src + "->" + dst
	acc, ok := dc.deps[key]
	if !ok {
		acc = &linkAccumulator{parent: src, child: dst}
		dc.deps[key] = acc
	}
	acc.callCount++
	// Connection events carry duration, use it as a latency proxy.
	if ev.DurationNs > 0 {
		acc.latencies = append(acc.latencies, ev.DurationNs)
	}
}

// addHTTPRequestEvent records an HTTP request event in the accumulator.
func (dc *DependencyComputer) addHTTPRequestEvent(ev *model.HTTPRequestEvent) {
	src := ev.Source.Service
	dst := ev.Destination.Service
	if src == "" || dst == "" || src == dst {
		return
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	key := src + "->" + dst
	acc, ok := dc.deps[key]
	if !ok {
		acc = &linkAccumulator{parent: src, child: dst}
		dc.deps[key] = acc
	}
	acc.callCount++
	if ev.StatusCode >= 500 {
		acc.errorCount++
	}
	if ev.LatencyNs > 0 {
		acc.latencies = append(acc.latencies, ev.LatencyNs)
	}
}

// buildLinks converts the accumulators into model.DependencyLink slices,
// computing P99 latencies.
func (dc *DependencyComputer) buildLinks() []model.DependencyLink {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	links := make([]model.DependencyLink, 0, len(dc.deps))
	for _, acc := range dc.deps {
		link := model.DependencyLink{
			Parent:       acc.parent,
			Child:        acc.child,
			CallCount:    acc.callCount,
			ErrorCount:   acc.errorCount,
			P99LatencyNs: computeP99(acc.latencies),
		}
		links = append(links, link)
	}
	return links
}

// computeP99 calculates the 99th percentile latency from a slice of
// latency values using a sorted-slice approach.
func computeP99(latencies []uint64) uint64 {
	n := len(latencies)
	if n == 0 {
		return 0
	}

	// Sort a copy to avoid mutating the original.
	sorted := make([]uint64, n)
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// P99 index: ceil(0.99 * n) - 1, clamped to valid range.
	idx := int(float64(n)*0.99+0.5) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// GetCurrentLinks returns a snapshot of the most recently computed
// dependency links. Thread-safe.
func (dc *DependencyComputer) GetCurrentLinks() []model.DependencyLink {
	return dc.buildLinks()
}
