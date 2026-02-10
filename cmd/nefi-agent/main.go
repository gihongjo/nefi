package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"go.uber.org/zap"

	ebpfloader "github.com/gihongjo/nefi/internal/agent/ebpf"
	"github.com/gihongjo/nefi/internal/agent/exporter"
	"github.com/gihongjo/nefi/internal/agent/k8s"
	"github.com/gihongjo/nefi/internal/model"
)

const (
	// defaultServerAddr is the default nefi-server gRPC endpoint.
	defaultServerAddr = "nefi-server:9090"

	// defaultEBPFObjectPath is the default path to the compiled eBPF objects directory.
	defaultEBPFObjectPath = "/opt/nefi/bpf"

	// healthAddr is the address for the health check HTTP endpoint.
	healthAddr = ":8080"
)

func main() {
	// Initialize structured logger.
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Read configuration from environment variables.
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Fatal("NODE_NAME environment variable is required")
	}

	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = defaultServerAddr
	}

	kubeconfig := os.Getenv("KUBECONFIG")

	ebpfObjectPath := os.Getenv("EBPF_OBJECT_PATH")
	if ebpfObjectPath == "" {
		ebpfObjectPath = defaultEBPFObjectPath
	}

	logger.Info("nefi-agent starting",
		zap.String("node", nodeName),
		zap.String("server", serverAddr),
		zap.String("ebpf_object", ebpfObjectPath),
	)

	// Create a root context that is cancelled on SIGTERM or SIGINT.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		//OS에서 신호올 때 까지 기다림
		sig := <-sigCh
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// Initialize components.
	loader := ebpfloader.NewLoader(logger.Named("ebpf"), ebpfObjectPath)

	k8sCache, err := k8s.NewCache(logger.Named("k8s"), kubeconfig)
	if err != nil {
		logger.Fatal("failed to create k8s cache", zap.Error(err))
	}

	exp := exporter.NewExporter(logger.Named("exporter"), serverAddr, nodeName)

	// Start health check HTTP server.
	healthReady := &healthState{}
	go startHealthServer(logger.Named("health"), healthReady)

	// Use a WaitGroup to track goroutine lifecycle.
	var wg sync.WaitGroup

	// Start eBPF loader (best-effort: agent continues without eBPF if loading fails).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := loader.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("ebpf loader failed, agent will run without eBPF data collection",
				zap.Error(err))
			// Do NOT cancel — let the agent stay alive for health checks
			// and to be ready when eBPF becomes available (e.g., after node upgrade).
		}
	}()

	// Start K8s informer cache.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := k8sCache.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Error("k8s cache failed", zap.Error(err))
			cancel()
		}
	}()

	// Start gRPC exporter.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := exp.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Error("grpc exporter failed", zap.Error(err))
			cancel()
		}
	}()

	// Mark the agent as ready once all components are started.
	healthReady.setReady(true)
	logger.Info("nefi-agent is ready")

	// Main event processing loop: read events from eBPF, enrich with K8s
	// metadata, and forward to the gRPC exporter.
	// Runs in a goroutine so the agent doesn't exit if eBPF channel closes early.
	wg.Add(1)
	go func() {
		defer wg.Done()
		processEvents(ctx, logger, loader, k8sCache, exp, nodeName)
	}()

	// Block until context is cancelled (signal received).
	<-ctx.Done()

	// Wait for all goroutines to finish.
	wg.Wait()
	logger.Info("nefi-agent shut down cleanly")
}

// processEvents reads events from the eBPF loader's channel, enriches them
// with Kubernetes metadata from the cache, and enqueues them for export.
func processEvents(
	ctx context.Context,
	logger *zap.Logger,
	loader *ebpfloader.Loader,
	cache *k8s.Cache,
	exp *exporter.Exporter,
	nodeName string,
) {
	events := loader.Events()

	for {
		select {
		case <-ctx.Done():
			return

		case evt, ok := <-events:
			if !ok {
				// Channel closed; eBPF loader has shut down.
				return
			}

			switch v := evt.(type) {
			case model.ConnectionEvent:
				enrichEndpoint(&v.Source, cache)
				enrichEndpoint(&v.Destination, cache)
				v.Node = nodeName
				exp.Enqueue(v)

			case model.HTTPRequestEvent:
				enrichEndpoint(&v.Source, cache)
				enrichEndpoint(&v.Destination, cache)
				v.Node = nodeName
				exp.Enqueue(v)

			default:
				logger.Warn("unknown event type from eBPF loader")
			}
		}
	}
}

// enrichEndpoint fills in the Kubernetes metadata fields of an Endpoint by
// looking up its IP in the K8s cache.
func enrichEndpoint(ep *model.Endpoint, cache *k8s.Cache) {
	if ep.IP == "" {
		return
	}

	cached := cache.Lookup(ep.IP)
	if cached == nil {
		return
	}

	ep.Pod = cached.Pod
	ep.Namespace = cached.Namespace
	ep.Workload = cached.Workload
	ep.WorkloadType = cached.WorkloadType
	ep.Service = cached.Service
}

// ---------------------------------------------------------------------------
// Health check HTTP server
// ---------------------------------------------------------------------------

// healthState tracks whether the agent is ready to serve.
type healthState struct {
	mu    sync.RWMutex
	ready bool
}

func (h *healthState) setReady(ready bool) {
	h.mu.Lock()
	h.ready = ready
	h.mu.Unlock()
}

func (h *healthState) isReady() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ready
}

// startHealthServer starts a minimal HTTP server that exposes /healthz and
// /readyz endpoints on the healthAddr port.
func startHealthServer(logger *zap.Logger, state *healthState) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if state.isReady() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready"))
		}
	})

	server := &http.Server{
		Addr:    healthAddr,
		Handler: mux,
	}

	logger.Info("health server starting", zap.String("addr", healthAddr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("health server failed", zap.Error(err))
	}
}
