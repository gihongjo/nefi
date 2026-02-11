package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"

	agentebpf "github.com/gihongjo/nefi/internal/agent/ebpf"
)

func main() {
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

		// Print event with protocol tag.
		dir := event.DirectionString()
		comm := event.CommString()
		proto := event.Protocol.String()

		if comm == "nefi-server" {

			fmt.Printf("  %s | pid=%-6d fd=%-4d size=%-6d proto=%-7s [%s]\n",
				dir, event.PID, event.FD, event.MsgSize, proto, comm)
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

		// Show printable ASCII payload.

	}

	fmt.Println("[*] Done.")
}
