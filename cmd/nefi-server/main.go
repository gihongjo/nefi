package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/gihongjo/nefi/internal/server/api"
	"github.com/gihongjo/nefi/internal/server/graph"
	"github.com/gihongjo/nefi/internal/server/ingestion"
	"github.com/gihongjo/nefi/internal/server/metrics"
	"github.com/gihongjo/nefi/internal/server/storage/elasticsearch"
)

func main() {
	// Initialize structured logger.
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Parse configuration from environment variables.
	esAddresses := getEnvOrDefault("ES_ADDRESSES", "http://localhost:9200")
	grpcPort := getEnvOrDefault("GRPC_PORT", "9090")
	httpPort := getEnvOrDefault("HTTP_PORT", "8080")

	addresses := strings.Split(esAddresses, ",")
	for i := range addresses {
		addresses[i] = strings.TrimSpace(addresses[i])
	}

	logger.Info("starting nefi-server",
		zap.Strings("esAddresses", addresses),
		zap.String("grpcPort", grpcPort),
		zap.String("httpPort", httpPort),
	)

	// 엘라스틱 서치 초기화. 추후 다른 방식으로 초기화도 생각 중.
	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses:     addresses,
		BatchSize:     elasticsearch.DefaultBatchSize,
		FlushInterval: elasticsearch.DefaultFlushInterval,
	}, logger)
	if err != nil {
		logger.Fatal("failed to create elasticsearch client", zap.Error(err))
	}

	//
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := esClient.EnsureIndices(ctx); err != nil {
		logger.Warn("failed to ensure index templates (ES may not be available yet)",
			zap.Error(err),
		)
	}
	cancel()

	// Initialize metrics aggregator.
	aggregator := metrics.NewAggregator(esClient, logger)
	aggregator.Start()

	// Initialize dependency graph computer.
	depComputer := graph.NewDependencyComputer(esClient, esClient, logger)
	depComputer.Start()

	// Initialize gRPC ingestion server.
	ingestionServer := ingestion.NewIngestionServer(esClient, aggregator, logger)

	grpcServer := grpc.NewServer()
	ingestion.RegisterEventIngestionServer(grpcServer, ingestionServer)

	// Initialize REST API + WebSocket handler.
	apiHandler := api.NewHandler(esClient, esClient, esClient, esClient, logger)
	apiHandler.StartTopologyBroadcast()

	httpServer := &http.Server{
		Addr:         ":" + httpPort,
		Handler:      apiHandler.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to collect startup errors.
	errCh := make(chan error, 2)

	// Start gRPC server.
	go func() {
		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			errCh <- fmt.Errorf("failed to listen on gRPC port %s: %w", grpcPort, err)
			return
		}
		logger.Info("gRPC server listening", zap.String("addr", lis.Addr().String()))
		if err := grpcServer.Serve(lis); err != nil {
			errCh <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Start HTTP server.
	go func() {
		logger.Info("HTTP server listening", zap.String("addr", httpServer.Addr))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Wait for shutdown signal or startup error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
	case err := <-errCh:
		logger.Error("server startup error", zap.Error(err))
	}

	// Graceful shutdown.
	logger.Info("initiating graceful shutdown")

	// Stop accepting new connections.
	grpcServer.GracefulStop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	// Stop background workers.
	apiHandler.StopTopologyBroadcast()
	depComputer.Stop()
	aggregator.Stop()

	// Close storage client (flushes remaining data).
	if err := esClient.Close(); err != nil {
		logger.Error("failed to close elasticsearch client", zap.Error(err))
	}

	logger.Info("nefi-server stopped")
}

// getEnvOrDefault returns the value of an environment variable, or
// the provided default if the variable is not set or empty.
func getEnvOrDefault(key, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}
