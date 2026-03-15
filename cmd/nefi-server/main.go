// nefi-server — 이벤트 수집 및 실시간 스트리밍 서버
//
// 흐름:
//
//	agent -[gRPC stream]-> CollectorService -> Store -> Hub -[WebSocket]-> browser/mobile
//	                                                 -> Aggregator -[WebSocket stats]-> browser/mobile
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/gihongjo/nefi/internal/server/app"
)

func main() {
	cfg := app.Config{}
	flag.StringVar(&cfg.GRPCAddr, "grpc-addr", ":9090", "gRPC listen address (agent → server)")
	flag.StringVar(&cfg.HTTPAddr, "http-addr", ":8080", "HTTP listen address (WebSocket /ws, API /api/...)")
	flag.IntVar(&cfg.Capacity, "capacity", 10000, "in-memory ring buffer capacity")
	flag.Parse()

	fmt.Println("============================================================")
	fmt.Println("  Nefi Server — gRPC Collector + WebSocket Hub")
	fmt.Println("============================================================")
	fmt.Printf("[+] gRPC: %s  HTTP: %s  capacity: %d\n", cfg.GRPCAddr, cfg.HTTPAddr, cfg.Capacity)

	srv, err := app.New(cfg)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server error: %v", err)
	}
	fmt.Println("[*] Done.")
}
