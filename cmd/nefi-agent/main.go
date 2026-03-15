// main.go — nefi-agent 진입점
//
// 역할:
//   에이전트의 시작부터 종료까지 전체 생명주기를 관리하고,
//   BPF로부터 올라오는 이벤트를 읽어 stdout에 출력한다.
//
// 흐름:
//   1. Loader 초기화 (internal/agent/ebpf)
//      → BPF 프로그램 로드 + syscall tracepoint attach + ringbuf 구독
//
//   2. SSLLoader + ProcScanner 초기화
//      → ssl_trace.c BPF 로드 (loader의 ringbuf 공유)
//      → ProcScanner 백그라운드 고루틴 시작 (5초마다 /proc 스캔)
//      → 실패해도 에이전트는 계속 동작 (TLS 캡처만 비활성화)
//
//   3. 이벤트 루프 (for)
//      → loader.Read()로 ringbuf에서 이벤트 블로킹 대기
//      → 이벤트 도착 시 방향/PID/FD/프로토콜/페이로드 출력
//      → ringbuf.ErrClosed 수신 시 (Ctrl+C 등) 루프 종료
//
//   4. 종료
//      → SIGINT/SIGTERM 수신 → loader.Close() → ringbuf 닫힘 → 루프 탈출
//
// 출력 형식 예시:
//   SEND >>> | pid=1234   fd=7    size=80     proto=HTTP    type=REQ [curl]
//              | GET / HTTP/1.1\r\nHost: example.com...
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	agentebpf "github.com/gihongjo/nefi/internal/agent/ebpf"
	agentgrpc "github.com/gihongjo/nefi/internal/agent/grpc"
	agentk8s "github.com/gihongjo/nefi/internal/agent/k8s"
	"github.com/gihongjo/nefi/internal/model"
)

func main() {
	serverAddr := flag.String("server-addr", "", "nefi-server gRPC address (e.g. nefi-server:9090); empty = stdout only")
	flag.Parse()

	fmt.Println("============================================================")
	fmt.Println("  Nefi Agent — eBPF Socket Data Capture (libbpf/CO-RE)")
	fmt.Println("============================================================")

	loader, err := agentebpf.New()
	if err != nil {
		log.Fatalf("Failed to start BPF: %v", err)
	}
	defer loader.Close()

	fmt.Println("[+] BPF loaded and tracepoints attached!")
	fmt.Printf("[*] PID=%d\n", os.Getpid())

	// SSL/TLS uprobe — graceful degradation if unavailable (e.g. non-Linux).
	sslLoader, err := agentebpf.NewSSLLoader(loader.EventsMap())
	if err != nil {
		log.Printf("[WARN] SSL/TLS tracing disabled: %v", err)
	} else {
		defer sslLoader.Close()
		scanner := agentebpf.NewProcScanner(sslLoader, 5*time.Second)
		scanner.Start()
		defer scanner.Stop()
		fmt.Println("[+] SSL/TLS uprobe active (5 s scan interval)")
	}

	// K8s pod resolver — graceful degradation if not running in-cluster.
	resolver, err := agentk8s.NewResolver()
	if err != nil {
		log.Printf("[WARN] K8s resolver disabled: %v", err)
		resolver = nil
	} else {
		fmt.Println("[+] K8s pod resolver active")
	}

	// gRPC sender — nefi-server로 이벤트 전송 (--server-addr 지정 시 활성화)
	var sender *agentgrpc.Sender
	nodeName := os.Getenv("NODE_NAME")
	if *serverAddr != "" {
		sender = agentgrpc.New(*serverAddr, nodeName)
		defer sender.Close()
		fmt.Printf("[+] gRPC sender active → %s\n", *serverAddr)
	}

	fmt.Println("[*] Tracing socket I/O... Press Ctrl+C to stop.")
	fmt.Println()

	// Handle graceful shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\n[*] Shutting down...")
		loader.Close()
	}()

	for {
		event, err := loader.Read()

		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Error reading event: %v", err)
			continue
		}

		comm := event.CommString()

		if event.Protocol != model.ProtoHTTP {
			continue
		}

		// Resolve local pod (by PID → cgroup → UID).
		podLabel := comm
		if resolver != nil {
			if pod := resolver.Resolve(event.PID); pod != nil {
				podLabel = pod.Namespace + "/" + pod.PodName + " | " + comm
			}
		}

		// Resolve remote pod (by remote IP → cluster-wide podsByIP).
		remoteLabel := event.RemoteIPString()
		remoteNs, remotePodName := "", ""
		if resolver != nil && event.RemoteIP != 0 {
			if remotePod := resolver.ResolveIP(event.RemoteIP); remotePod != nil {
				remoteNs = remotePod.Namespace
				remotePodName = remotePod.PodName
				remoteLabel = remoteNs + "/" + remotePodName
			}
		}
		if event.RemotePort != 0 && remoteLabel != "" {
			remoteLabel = fmt.Sprintf("%s:%d", remoteLabel, event.RemotePort)
		}

		// Forward to nefi-server if sender is active.
		if sender != nil {
			namespace, podName := "", ""
			if resolver != nil {
				if pod := resolver.Resolve(event.PID); pod != nil {
					namespace = pod.Namespace
					podName = pod.PodName
				}
			}
			sender.Send(event, namespace, podName, remoteNs, remotePodName)
		}

		// Print event with protocol, message type, and remote endpoint.
		dir := event.DirectionString()
		proto := event.Protocol.String()
		msgType := event.MsgType.String()

		if remoteLabel != "" {
			fmt.Printf("  %s | pid=%-6d fd=%-4d size=%-6d proto=%-7s type=%-3s [%s] ↔ %s\n",
				dir, event.PID, event.FD, event.MsgSize, proto, msgType, podLabel, remoteLabel)
		} else {
			fmt.Printf("  %s | pid=%-6d fd=%-4d size=%-6d proto=%-7s type=%-3s [%s]\n",
				dir, event.PID, event.FD, event.MsgSize, proto, msgType, podLabel)
		}
		payload := event.Payload()
		if len(payload) > 0 {
			line := make([]byte, len(payload))
			for i, b := range payload {
				if b >= 32 && b < 127 {
					line[i] = b
				} else {
					line[i] = '.'
				}
			}
			fmt.Printf("           | %s\n", string(line))
		}

	}

	fmt.Println("[*] Done.")
}
