// Package app는 nefi-server의 모든 컴포넌트를 조립하고 생명주기를 관리한다.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	nefiv1 "github.com/gihongjo/nefi/gen/go/nefi/v1"
	"github.com/gihongjo/nefi/internal/server/aggregator"
	"github.com/gihongjo/nefi/internal/server/api"
	"github.com/gihongjo/nefi/internal/server/collector"
	"github.com/gihongjo/nefi/internal/server/hub"
	"github.com/gihongjo/nefi/internal/server/store"
	"github.com/gihongjo/nefi/web"
)

// Config는 서버 설정값을 담는다.
type Config struct {
	GRPCAddr string
	HTTPAddr string
	Capacity int
}

// Server는 nefi-server의 모든 컴포넌트를 소유한다.
type Server struct {
	cfg     Config
	store   store.Store
	agg     *aggregator.Aggregator
	hub     *hub.Hub
	grpcSrv *grpc.Server
	grpcLis net.Listener
	httpSrv *http.Server
}

// New는 컴포넌트를 초기화하고 포트를 바인딩한다.
// 실제 요청 처리는 Run() 호출 이후 시작된다.
func New(cfg Config) (*Server, error) {

	s := store.New(cfg.Capacity)
	agg := aggregator.New(s)
	h := hub.New(s, agg)

	grpcLis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		s.Close()
		agg.Close()
		h.Close()
		return nil, fmt.Errorf("gRPC listen %s: %w", cfg.GRPCAddr, err)
	}
	grpcSrv := grpc.NewServer()
	nefiv1.RegisterNefiCollectorServer(grpcSrv, collector.New(s))

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(cors.Default(), gin.Logger(), gin.Recovery())
	api.New(s, agg).Register(r)
	r.GET("/ws", gin.WrapH(h))

	// Svelte 빌드 결과물 (web/dist/) 서빙
	// SPA 라우팅: /assets/* 는 파일 그대로, 나머지는 index.html 반환
	distFS, _ := fs.Sub(web.Files, "dist")
	r.StaticFS("/assets", http.FS(mustSub(distFS, "assets")))
	r.NoRoute(func(c *gin.Context) {
		data, err := fs.ReadFile(distFS, "index.html")
		if err != nil {
			c.String(http.StatusServiceUnavailable, "UI not built — run: cd ui && npm run build")
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})

	return &Server{
		cfg:     cfg,
		store:   s,
		agg:     agg,
		hub:     h,
		grpcSrv: grpcSrv,
		grpcLis: grpcLis,
		httpSrv: &http.Server{Addr: cfg.HTTPAddr, Handler: r},
	}, nil
}

// Run은 두 서버를 기동하고 ctx가 취소되거나 에러가 발생할 때까지 블로킹한다.
// 반환 전에 모든 컴포넌트를 정리한다.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		log.Printf("[+] gRPC listening on %s", s.cfg.GRPCAddr)
		if err := s.grpcSrv.Serve(s.grpcLis); err != nil {
			errCh <- fmt.Errorf("gRPC: %w", err)
		}
	}()
	go func() {
		log.Printf("[+] HTTP/WebSocket listening on %s", s.cfg.HTTPAddr)
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	return s.shutdown(runErr)
}

// mustSub는 fs.Sub 결과를 반환하며 에러 시 nil FS를 반환한다.
func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return fsys
	}
	return sub
}

// shutdown은 gRPC → HTTP 순으로 종료하고 내부 컴포넌트를 정리한다.
func (s *Server) shutdown(cause error) error {
	log.Println("[*] Shutting down...")

	s.grpcSrv.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		log.Printf("[HTTP] shutdown error: %v", err)
	}

	// 외부 네트워크 연결 종료 후 내부 컴포넌트 정리
	s.hub.Close()
	s.agg.Close()
	s.store.Close()

	return cause
}
