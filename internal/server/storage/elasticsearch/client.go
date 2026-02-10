package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"

	"github.com/gihongjo/nefi/internal/model"
)

// Default configuration values.
const (
	DefaultBatchSize     = 1000
	DefaultFlushInterval = 5 * time.Second

	indexPrefixConnections  = "nefi-connections"
	indexPrefixRequests     = "nefi-requests"
	indexPrefixDependencies = "nefi-dependencies"
	indexPrefixMetrics      = "nefi-metrics"

	dateLayout = "2006-01-02"
)

// Config holds Elasticsearch client configuration.
type Config struct {
	Addresses     []string
	BatchSize     int
	FlushInterval time.Duration
}

// Client implements model.EventWriter, model.EventReader, model.DependencyReader,
// model.DependencyWriter, model.MetricReader, model.MetricWriter, and
// model.ServiceReader backed by Elasticsearch.
type Client struct {
	es     *elasticsearch.Client
	logger *zap.Logger

	batchSize     int
	flushInterval time.Duration

	// Bulk write buffer.
	mu      sync.Mutex
	buf     bytes.Buffer
	pending int
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewClient creates a new Elasticsearch storage client.
func NewClient(cfg Config, logger *zap.Logger) (*Client, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: cfg.Addresses,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch client: %w", err)
	}

	c := &Client{
		es:            es,
		logger:        logger.Named("elasticsearch"),
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	go c.flushLoop()

	return c, nil
}

// Close stops the background flusher and flushes remaining data.
func (c *Client) Close() error {
	close(c.stopCh)
	<-c.doneCh
	return c.flush()
}

// -----------------------------------------------------------------------
// Index management
// -----------------------------------------------------------------------

// EnsureIndices creates index templates for all nefi indices.
func (c *Client) EnsureIndices(ctx context.Context) error {
	templates := map[string]string{
		"nefi-connections":  connectionsTemplate,
		"nefi-requests":     requestsTemplate,
		"nefi-dependencies": dependenciesTemplate,
		"nefi-metrics":      metricsTemplate,
	}

	for name, body := range templates {
		req := esapi.IndicesPutIndexTemplateRequest{
			Name: name,
			Body: strings.NewReader(body),
		}
		res, err := req.Do(ctx, c.es)
		if err != nil {
			return fmt.Errorf("failed to create index template %s: %w", name, err)
		}
		res.Body.Close()
		if res.IsError() {
			return fmt.Errorf("error creating index template %s: %s", name, res.String())
		}
		c.logger.Info("created index template", zap.String("template", name))
	}

	return nil
}

// Index templates define mappings for each index pattern.
var connectionsTemplate = `{
	"index_patterns": ["nefi-connections-*"],
	"template": {
		"settings": {"number_of_shards": 1, "number_of_replicas": 1},
		"mappings": {
			"properties": {
				"timestamp":   {"type": "date"},
				"node":        {"type": "keyword"},
				"source":      {"properties": {
					"ip": {"type": "ip"}, "port": {"type": "integer"},
					"pod": {"type": "keyword"}, "namespace": {"type": "keyword"},
					"workload": {"type": "keyword"}, "workloadType": {"type": "keyword"},
					"service": {"type": "keyword"}
				}},
				"destination": {"properties": {
					"ip": {"type": "ip"}, "port": {"type": "integer"},
					"pod": {"type": "keyword"}, "namespace": {"type": "keyword"},
					"workload": {"type": "keyword"}, "workloadType": {"type": "keyword"},
					"service": {"type": "keyword"}
				}},
				"bytesSent":   {"type": "long"},
				"bytesRecv":   {"type": "long"},
				"durationNs":  {"type": "long"},
				"retransmits": {"type": "integer"},
				"protocol":    {"type": "keyword"}
			}
		}
	}
}`

var requestsTemplate = `{
	"index_patterns": ["nefi-requests-*"],
	"template": {
		"settings": {"number_of_shards": 1, "number_of_replicas": 1},
		"mappings": {
			"properties": {
				"timestamp":   {"type": "date"},
				"node":        {"type": "keyword"},
				"source":      {"properties": {
					"ip": {"type": "ip"}, "port": {"type": "integer"},
					"pod": {"type": "keyword"}, "namespace": {"type": "keyword"},
					"workload": {"type": "keyword"}, "workloadType": {"type": "keyword"},
					"service": {"type": "keyword"}
				}},
				"destination": {"properties": {
					"ip": {"type": "ip"}, "port": {"type": "integer"},
					"pod": {"type": "keyword"}, "namespace": {"type": "keyword"},
					"workload": {"type": "keyword"}, "workloadType": {"type": "keyword"},
					"service": {"type": "keyword"}
				}},
				"method":      {"type": "keyword"},
				"path":        {"type": "keyword"},
				"statusCode":  {"type": "integer"},
				"latencyNs":   {"type": "long"},
				"protocol":    {"type": "keyword"}
			}
		}
	}
}`

var dependenciesTemplate = `{
	"index_patterns": ["nefi-dependencies-*"],
	"template": {
		"settings": {"number_of_shards": 1, "number_of_replicas": 1},
		"mappings": {
			"properties": {
				"parent":       {"type": "keyword"},
				"child":        {"type": "keyword"},
				"callCount":    {"type": "long"},
				"errorCount":   {"type": "long"},
				"p99LatencyNs": {"type": "long"},
				"timestamp":    {"type": "date"}
			}
		}
	}
}`

var metricsTemplate = `{
	"index_patterns": ["nefi-metrics-*"],
	"template": {
		"settings": {"number_of_shards": 1, "number_of_replicas": 1},
		"mappings": {
			"properties": {
				"timestamp":  {"type": "date"},
				"value":      {"type": "double"},
				"labels":     {"type": "object", "enabled": true},
				"metricType": {"type": "keyword"}
			}
		}
	}
}`

// -----------------------------------------------------------------------
// Bulk write helpers
// -----------------------------------------------------------------------

// flushLoop periodically flushes the bulk buffer.
func (c *Client) flushLoop() {
	defer close(c.doneCh)
	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.flush(); err != nil {
				c.logger.Error("periodic flush failed", zap.Error(err))
			}
		case <-c.stopCh:
			return
		}
	}
}

// addBulkAction appends a bulk index action to the buffer and flushes
// when the batch size is reached.
func (c *Client) addBulkAction(index string, doc interface{}) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	meta := fmt.Sprintf(`{"index":{"_index":"%s"}}`, index)

	c.mu.Lock()
	c.buf.WriteString(meta)
	c.buf.WriteByte('\n')
	c.buf.Write(data)
	c.buf.WriteByte('\n')
	c.pending++
	shouldFlush := c.pending >= c.batchSize
	c.mu.Unlock()

	if shouldFlush {
		return c.flush()
	}
	return nil
}

// flush sends the current bulk buffer to Elasticsearch.
func (c *Client) flush() error {
	c.mu.Lock()
	if c.pending == 0 {
		c.mu.Unlock()
		return nil
	}
	body := c.buf.String()
	count := c.pending
	c.buf.Reset()
	c.pending = 0
	c.mu.Unlock()

	res, err := c.es.Bulk(strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("bulk request failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("bulk request error: %s", res.String())
	}

	c.logger.Debug("flushed bulk buffer", zap.Int("documents", count))
	return nil
}

// indexName returns a date-suffixed index name.
func indexName(prefix string, t time.Time) string {
	return prefix + "-" + t.UTC().Format(dateLayout)
}

// indexPattern returns a wildcard pattern for an index prefix with optional
// date range filtering (resolved at query time via the time filter).
func indexPattern(prefix string) string {
	return prefix + "-*"
}

// -----------------------------------------------------------------------
// EventWriter implementation
// -----------------------------------------------------------------------

// WriteConnectionEvents writes connection events to Elasticsearch.
func (c *Client) WriteConnectionEvents(ctx context.Context, events []model.ConnectionEvent) error {
	for i := range events {
		idx := indexName(indexPrefixConnections, events[i].Timestamp)
		if err := c.addBulkAction(idx, &events[i]); err != nil {
			return err
		}
	}
	return nil
}

// WriteHTTPRequestEvents writes HTTP request events to Elasticsearch.
func (c *Client) WriteHTTPRequestEvents(ctx context.Context, events []model.HTTPRequestEvent) error {
	for i := range events {
		idx := indexName(indexPrefixRequests, events[i].Timestamp)
		if err := c.addBulkAction(idx, &events[i]); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------
// EventReader implementation
// -----------------------------------------------------------------------

// FindConnections queries connection events matching the given filters.
func (c *Client) FindConnections(ctx context.Context, query model.EventQuery) ([]model.ConnectionEvent, error) {
	esQuery := buildEventQuery(query)
	body, err := json.Marshal(esQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(indexPattern(indexPrefixConnections)),
		c.es.Search.WithBody(bytes.NewReader(body)),
		c.es.Search.WithSize(limit),
		c.es.Search.WithSort("timestamp:desc"),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result searchResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	events := make([]model.ConnectionEvent, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		var ev model.ConnectionEvent
		if err := json.Unmarshal(hit.Source, &ev); err != nil {
			c.logger.Warn("failed to unmarshal connection event", zap.Error(err))
			continue
		}
		events = append(events, ev)
	}
	return events, nil
}

// FindRequests queries HTTP request events matching the given filters.
func (c *Client) FindRequests(ctx context.Context, query model.EventQuery) ([]model.HTTPRequestEvent, error) {
	esQuery := buildEventQuery(query)
	body, err := json.Marshal(esQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(indexPattern(indexPrefixRequests)),
		c.es.Search.WithBody(bytes.NewReader(body)),
		c.es.Search.WithSize(limit),
		c.es.Search.WithSort("timestamp:desc"),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result searchResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	events := make([]model.HTTPRequestEvent, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		var ev model.HTTPRequestEvent
		if err := json.Unmarshal(hit.Source, &ev); err != nil {
			c.logger.Warn("failed to unmarshal request event", zap.Error(err))
			continue
		}
		events = append(events, ev)
	}
	return events, nil
}

// -----------------------------------------------------------------------
// DependencyWriter implementation
// -----------------------------------------------------------------------

// WriteDependencies writes computed dependency links to Elasticsearch.
func (c *Client) WriteDependencies(ctx context.Context, deps []model.DependencyLink) error {
	now := time.Now()
	idx := indexName(indexPrefixDependencies, now)

	type depDoc struct {
		model.DependencyLink
		Timestamp time.Time `json:"timestamp"`
	}

	for i := range deps {
		doc := depDoc{
			DependencyLink: deps[i],
			Timestamp:      now,
		}
		if err := c.addBulkAction(idx, &doc); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------
// DependencyReader implementation
// -----------------------------------------------------------------------

// GetDependencies queries dependency links matching the given filters.
func (c *Client) GetDependencies(ctx context.Context, query model.DependencyQuery) ([]model.DependencyLink, error) {
	esQuery := buildDependencyQuery(query)
	body, err := json.Marshal(esQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(indexPattern(indexPrefixDependencies)),
		c.es.Search.WithBody(bytes.NewReader(body)),
		c.es.Search.WithSize(10000),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result searchResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	deps := make([]model.DependencyLink, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		var dep model.DependencyLink
		if err := json.Unmarshal(hit.Source, &dep); err != nil {
			c.logger.Warn("failed to unmarshal dependency link", zap.Error(err))
			continue
		}
		deps = append(deps, dep)
	}
	return deps, nil
}

// -----------------------------------------------------------------------
// MetricWriter implementation
// -----------------------------------------------------------------------

// WriteMetrics writes aggregated metric time series points to Elasticsearch.
func (c *Client) WriteMetrics(ctx context.Context, points []model.TimeSeriesPoint, metricType string) error {
	for i := range points {
		idx := indexName(indexPrefixMetrics, points[i].Timestamp)
		doc := metricDoc{
			TimeSeriesPoint: points[i],
			MetricType:      metricType,
		}
		if err := c.addBulkAction(idx, &doc); err != nil {
			return err
		}
	}
	return nil
}

type metricDoc struct {
	model.TimeSeriesPoint
	MetricType string `json:"metricType"`
}

// -----------------------------------------------------------------------
// MetricReader implementation
// -----------------------------------------------------------------------

// GetLatencies queries latency metric time series.
func (c *Client) GetLatencies(ctx context.Context, params model.MetricQuery) ([]model.TimeSeriesPoint, error) {
	return c.queryMetrics(ctx, "latency", params)
}

// GetCallRates queries call rate metric time series.
func (c *Client) GetCallRates(ctx context.Context, params model.MetricQuery) ([]model.TimeSeriesPoint, error) {
	return c.queryMetrics(ctx, "call_rate", params)
}

// GetErrorRates queries error rate metric time series.
func (c *Client) GetErrorRates(ctx context.Context, params model.MetricQuery) ([]model.TimeSeriesPoint, error) {
	return c.queryMetrics(ctx, "error_rate", params)
}

func (c *Client) queryMetrics(ctx context.Context, metricType string, params model.MetricQuery) ([]model.TimeSeriesPoint, error) {
	esQuery := buildMetricQuery(metricType, params)
	body, err := json.Marshal(esQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(indexPattern(indexPrefixMetrics)),
		c.es.Search.WithBody(bytes.NewReader(body)),
		c.es.Search.WithSize(10000),
		c.es.Search.WithSort("timestamp:asc"),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result searchResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	points := make([]model.TimeSeriesPoint, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		var pt model.TimeSeriesPoint
		if err := json.Unmarshal(hit.Source, &pt); err != nil {
			c.logger.Warn("failed to unmarshal metric point", zap.Error(err))
			continue
		}
		points = append(points, pt)
	}
	return points, nil
}

// -----------------------------------------------------------------------
// ServiceReader implementation
// -----------------------------------------------------------------------

// GetServices returns a list of all distinct service names from connection
// and request events.
func (c *Client) GetServices(ctx context.Context) ([]string, error) {
	query := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"services": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "source.service",
					"size":  10000,
				},
			},
			"dst_services": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "destination.service",
					"size":  10000,
				},
			},
		},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	indices := indexPattern(indexPrefixConnections) + "," + indexPattern(indexPrefixRequests)
	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(indices),
		c.es.Search.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result aggsResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	serviceSet := make(map[string]struct{})
	for _, bucket := range result.Aggregations.Services.Buckets {
		if bucket.Key != "" {
			serviceSet[bucket.Key] = struct{}{}
		}
	}
	for _, bucket := range result.Aggregations.DstServices.Buckets {
		if bucket.Key != "" {
			serviceSet[bucket.Key] = struct{}{}
		}
	}

	services := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		services = append(services, svc)
	}
	return services, nil
}

// GetOperations returns a list of distinct HTTP paths (operations) for
// a given service.
func (c *Client) GetOperations(ctx context.Context, service string) ([]string, error) {
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"source.service": service}},
					{"term": map[string]interface{}{"destination.service": service}},
				},
				"minimum_should_match": 1,
			},
		},
		"aggs": map[string]interface{}{
			"operations": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "path",
					"size":  10000,
				},
			},
		},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(indexPattern(indexPrefixRequests)),
		c.es.Search.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result struct {
		Aggregations struct {
			Operations struct {
				Buckets []aggBucket `json:"buckets"`
			} `json:"operations"`
		} `json:"aggregations"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	ops := make([]string, 0, len(result.Aggregations.Operations.Buckets))
	for _, bucket := range result.Aggregations.Operations.Buckets {
		ops = append(ops, bucket.Key)
	}
	return ops, nil
}

// -----------------------------------------------------------------------
// Query builders
// -----------------------------------------------------------------------

func buildEventQuery(q model.EventQuery) map[string]interface{} {
	filters := make([]map[string]interface{}, 0, 4)

	// Time range filter.
	if !q.StartTime.IsZero() || !q.EndTime.IsZero() {
		rangeFilter := make(map[string]interface{})
		if !q.StartTime.IsZero() {
			rangeFilter["gte"] = q.StartTime.Format(time.RFC3339Nano)
		}
		if !q.EndTime.IsZero() {
			rangeFilter["lte"] = q.EndTime.Format(time.RFC3339Nano)
		}
		filters = append(filters, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": rangeFilter,
			},
		})
	}

	// Service filter: match on either source or destination service.
	if q.Service != "" {
		filters = append(filters, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"source.service": q.Service}},
					{"term": map[string]interface{}{"destination.service": q.Service}},
				},
				"minimum_should_match": 1,
			},
		})
	}

	// Namespace filter.
	if q.Namespace != "" {
		filters = append(filters, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"source.namespace": q.Namespace}},
					{"term": map[string]interface{}{"destination.namespace": q.Namespace}},
				},
				"minimum_should_match": 1,
			},
		})
	}

	// Specific source filter.
	if q.Source != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{"source.service": q.Source},
		})
	}

	// Specific destination filter.
	if q.Destination != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{"destination.service": q.Destination},
		})
	}

	if len(filters) == 0 {
		return map[string]interface{}{
			"query": map[string]interface{}{
				"match_all": map[string]interface{}{},
			},
		}
	}

	return map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filters,
			},
		},
	}
}

func buildDependencyQuery(q model.DependencyQuery) map[string]interface{} {
	filters := make([]map[string]interface{}, 0, 2)

	if !q.StartTime.IsZero() || !q.EndTime.IsZero() {
		rangeFilter := make(map[string]interface{})
		if !q.StartTime.IsZero() {
			rangeFilter["gte"] = q.StartTime.Format(time.RFC3339Nano)
		}
		if !q.EndTime.IsZero() {
			rangeFilter["lte"] = q.EndTime.Format(time.RFC3339Nano)
		}
		filters = append(filters, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": rangeFilter,
			},
		})
	}

	if q.Service != "" {
		filters = append(filters, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"parent": q.Service}},
					{"term": map[string]interface{}{"child": q.Service}},
				},
				"minimum_should_match": 1,
			},
		})
	}

	if len(filters) == 0 {
		return map[string]interface{}{
			"query": map[string]interface{}{
				"match_all": map[string]interface{}{},
			},
		}
	}

	return map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filters,
			},
		},
	}
}

func buildMetricQuery(metricType string, q model.MetricQuery) map[string]interface{} {
	filters := []map[string]interface{}{
		{"term": map[string]interface{}{"metricType": metricType}},
	}

	if !q.StartTime.IsZero() || !q.EndTime.IsZero() {
		rangeFilter := make(map[string]interface{})
		if !q.StartTime.IsZero() {
			rangeFilter["gte"] = q.StartTime.Format(time.RFC3339Nano)
		}
		if !q.EndTime.IsZero() {
			rangeFilter["lte"] = q.EndTime.Format(time.RFC3339Nano)
		}
		filters = append(filters, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": rangeFilter,
			},
		})
	}

	if q.Service != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{"labels.service": q.Service},
		})
	}

	if q.Namespace != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{"labels.namespace": q.Namespace},
		})
	}

	return map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filters,
			},
		},
	}
}

// -----------------------------------------------------------------------
// Elasticsearch response types
// -----------------------------------------------------------------------

type searchResult struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []searchHit `json:"hits"`
	} `json:"hits"`
}

type searchHit struct {
	Index  string          `json:"_index"`
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
}

type aggsResult struct {
	Aggregations struct {
		Services struct {
			Buckets []aggBucket `json:"buckets"`
		} `json:"services"`
		DstServices struct {
			Buckets []aggBucket `json:"buckets"`
		} `json:"dst_services"`
	} `json:"aggregations"`
}

type aggBucket struct {
	Key      string `json:"key"`
	DocCount int    `json:"doc_count"`
}

// Compile-time interface assertions.
var (
	_ model.EventWriter      = (*Client)(nil)
	_ model.EventReader      = (*Client)(nil)
	_ model.DependencyReader = (*Client)(nil)
	_ model.DependencyWriter = (*Client)(nil)
	_ model.MetricReader     = (*Client)(nil)
	_ model.MetricWriter     = (*Client)(nil)
	_ model.ServiceReader    = (*Client)(nil)
)
