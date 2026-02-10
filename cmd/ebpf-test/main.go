package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// ConnEvent mirrors the C struct conn_event in bpf/headers/common.h.
type ConnEvent struct {
	TimestampNs uint64
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	BytesSent   uint64
	BytesRecv   uint64
	DurationNs  uint64
	Retransmits uint32
	Protocol    uint8
	Pad         [3]uint8
}

func main() {
	objPath := "/opt/nefi/bpf"
	if len(os.Args) > 1 {
		objPath = os.Args[1]
	}

	objFile := filepath.Join(objPath, "connection_tracker.o")
	fmt.Printf("Loading eBPF object: %s\n", objFile)

	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load spec: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Spec loaded. Programs: ")
	for name := range spec.Programs {
		fmt.Printf("%s ", name)
	}
	fmt.Printf("\nMaps: ")
	for name := range spec.Maps {
		fmt.Printf("%s ", name)
	}
	fmt.Println()

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()
	fmt.Println("Collection created OK")

	// Attach tracepoint: sock/inet_sock_set_state
	prog := coll.Programs["trace_inet_sock_set_state"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "Program trace_inet_sock_set_state not found\n")
		os.Exit(1)
	}
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint: %v\n", err)
		os.Exit(1)
	}
	defer tp.Close()
	fmt.Println("Attached: tracepoint/sock/inet_sock_set_state")

	// Attach tracepoint: tcp/tcp_retransmit_skb (optional)
	if retransProg := coll.Programs["trace_tcp_retransmit"]; retransProg != nil {
		tp2, err := link.Tracepoint("tcp", "tcp_retransmit_skb", retransProg, nil)
		if err != nil {
			fmt.Printf("Warning: failed to attach tcp_retransmit_skb: %v\n", err)
		} else {
			defer tp2.Close()
			fmt.Println("Attached: tracepoint/tcp/tcp_retransmit_skb")
		}
	}

	// Open perf reader for conn_events
	perfMap := coll.Maps["conn_events"]
	if perfMap == nil {
		fmt.Fprintf(os.Stderr, "conn_events map not found\n")
		os.Exit(1)
	}
	reader, err := perf.NewReader(perfMap, 256*1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create perf reader: %v\n", err)
		os.Exit(1)
	}
	defer reader.Close()

	fmt.Println("Perf reader ready. Waiting for TCP connections...")
	fmt.Println("(Generate traffic with: curl google.com)")
	fmt.Println("---")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
		reader.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("Perf read error: %v\n", err)
			return
		}
		if record.LostSamples > 0 {
			fmt.Printf("Lost %d samples\n", record.LostSamples)
			continue
		}

		raw := record.RawSample
		if len(raw) < 49 {
			fmt.Printf("Sample too small: %d bytes\n", len(raw))
			continue
		}

		srcIP := intToIPv4(binary.LittleEndian.Uint32(raw[8:12]))
		dstIP := intToIPv4(binary.LittleEndian.Uint32(raw[12:16]))
		srcPort := binary.LittleEndian.Uint16(raw[16:18])
		dstPort := binary.LittleEndian.Uint16(raw[18:20])
		bytesSent := binary.LittleEndian.Uint64(raw[20:28])
		bytesRecv := binary.LittleEndian.Uint64(raw[28:36])
		durationNs := binary.LittleEndian.Uint64(raw[36:44])
		retransmits := binary.LittleEndian.Uint32(raw[44:48])

		durationMs := float64(durationNs) / 1_000_000.0

		fmt.Printf("CONN %s:%d → %s:%d | sent=%d recv=%d duration=%.1fms retrans=%d\n",
			srcIP, srcPort, dstIP, dstPort,
			bytesSent, bytesRecv, durationMs, retransmits)
	}
}

func intToIPv4(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}
