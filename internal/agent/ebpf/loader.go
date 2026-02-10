package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"

	"github.com/gihongjo/nefi/internal/model"
)

// ConnEvent mirrors the C struct conn_event (packed) in bpf/headers/common.h.
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

// HttpEvent mirrors the C struct http_event (packed) in bpf/headers/common.h.
type HttpEvent struct {
	TimestampNs uint64
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Method      uint8
	StatusCode  uint16
	LatencyNs   uint64
	Path        [128]byte
	Pad         [1]uint8
}

// httpMethods maps the method byte from the eBPF struct to an HTTP method string.
var httpMethods = map[uint8]string{
	0: "UNKNOWN",
	1: "GET",
	2: "POST",
	3: "PUT",
	4: "DELETE",
	5: "PATCH",
	6: "HEAD",
	7: "OPTIONS",
}

// programAttach defines how an eBPF program should be attached to the kernel.
type programAttach struct {
	// progName is the function name in the eBPF C source (SEC name symbol).
	progName string
	// attachType: "tracepoint", "kprobe", "kretprobe"
	attachType string
	// group is the tracepoint group (e.g., "sock", "tcp"). Empty for kprobes.
	group string
	// name is the tracepoint name or kernel function name.
	name string
}

// attachMap defines all known eBPF programs and how to attach them.
var attachMap = []programAttach{
	// connection_tracker.c
	{progName: "trace_inet_sock_set_state", attachType: "tracepoint", group: "sock", name: "inet_sock_set_state"},
	{progName: "trace_tcp_retransmit", attachType: "tracepoint", group: "tcp", name: "tcp_retransmit_skb"},
	// http_parser.c
	{progName: "trace_tcp_sendmsg", attachType: "kprobe", name: "tcp_sendmsg"},
	{progName: "trace_tcp_recvmsg_enter", attachType: "kprobe", name: "tcp_recvmsg"},
	{progName: "trace_tcp_recvmsg_exit", attachType: "kretprobe", name: "tcp_recvmsg"},
	// dns_tracker.c
	{progName: "trace_udp_sendmsg", attachType: "kprobe", name: "udp_sendmsg"},
}

// Loader manages eBPF program loading, attachment, and perf buffer event reading.
type Loader struct {
	logger      *zap.Logger
	objPath     string
	events      chan interface{}
	connPerf    *perf.Reader
	httpPerf    *perf.Reader
	collections []*ebpf.Collection
	links       []io.Closer
}

// NewLoader creates a new eBPF Loader.
func NewLoader(logger *zap.Logger, objPath string) *Loader {
	return &Loader{
		logger:  logger,
		objPath: objPath,
		events:  make(chan interface{}, 4096),
	}
}

// Events returns a read-only channel that emits model.ConnectionEvent and
// model.HTTPRequestEvent as they are read from the eBPF perf buffers.
func (l *Loader) Events() <-chan interface{} {
	return l.events
}

// Start loads the eBPF programs, attaches them to their hooks, opens perf
// buffers, and begins reading events. It blocks until ctx is cancelled.
func (l *Loader) Start(ctx context.Context) error {
	specs, err := l.loadSpecs()
	if err != nil {
		return fmt.Errorf("failed to load eBPF specs from %s: %w", l.objPath, err)
	}
	if len(specs) == 0 {
		return fmt.Errorf("no eBPF object files found at %s", l.objPath)
	}

	for path, spec := range specs {
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			l.logger.Warn("failed to create eBPF collection, skipping",
				zap.String("path", path), zap.Error(err))
			continue
		}
		l.collections = append(l.collections, coll)

		// Attach programs to their kernel hooks.
		l.attachPrograms(coll)

		// Open perf readers.
		if m := coll.Maps["conn_events"]; m != nil && l.connPerf == nil {
			reader, err := perf.NewReader(m, 256*1024)
			if err != nil {
				l.logger.Warn("failed to create conn_events perf reader", zap.Error(err))
			} else {
				l.connPerf = reader
			}
		}
		if m := coll.Maps["http_events"]; m != nil && l.httpPerf == nil {
			reader, err := perf.NewReader(m, 256*1024)
			if err != nil {
				l.logger.Warn("failed to create http_events perf reader", zap.Error(err))
			} else {
				l.httpPerf = reader
			}
		}
	}

	if l.connPerf == nil && l.httpPerf == nil {
		return fmt.Errorf("no perf buffers could be opened from eBPF objects at %s", l.objPath)
	}

	l.logger.Info("eBPF programs loaded and attached",
		zap.String("path", l.objPath),
		zap.Int("links", len(l.links)),
		zap.Bool("conn_events", l.connPerf != nil),
		zap.Bool("http_events", l.httpPerf != nil))

	if l.connPerf != nil {
		go l.readConnEvents(ctx)
	}
	if l.httpPerf != nil {
		go l.readHTTPEvents(ctx)
	}

	<-ctx.Done()
	l.Close()
	return ctx.Err()
}

// attachPrograms iterates the collection's programs and attaches each one
// that has an entry in the attachMap.
func (l *Loader) attachPrograms(coll *ebpf.Collection) {
	for _, a := range attachMap {
		prog, ok := coll.Programs[a.progName]
		if !ok {
			continue
		}

		var (
			lnk link.Link
			err error
		)

		switch a.attachType {
		case "tracepoint":
			lnk, err = link.Tracepoint(a.group, a.name, prog, nil)
		case "kprobe":
			lnk, err = link.Kprobe(a.name, prog, nil)
		case "kretprobe":
			lnk, err = link.Kretprobe(a.name, prog, nil)
		default:
			l.logger.Warn("unknown attach type", zap.String("type", a.attachType))
			continue
		}

		if err != nil {
			l.logger.Warn("failed to attach eBPF program",
				zap.String("program", a.progName),
				zap.String("type", a.attachType),
				zap.String("target", a.group+"/"+a.name),
				zap.Error(err))
			continue
		}

		l.links = append(l.links, lnk)
		l.logger.Info("attached eBPF program",
			zap.String("program", a.progName),
			zap.String("target", strings.TrimLeft(a.group+"/"+a.name, "/")))
	}
}

// loadSpecs discovers and loads eBPF CollectionSpecs from the configured path.
func (l *Loader) loadSpecs() (map[string]*ebpf.CollectionSpec, error) {
	specs := make(map[string]*ebpf.CollectionSpec)

	info, err := os.Stat(l.objPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		files, err := filepath.Glob(filepath.Join(l.objPath, "*.o"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			spec, err := ebpf.LoadCollectionSpec(f)
			if err != nil {
				l.logger.Warn("failed to load eBPF spec, skipping",
					zap.String("file", f), zap.Error(err))
				continue
			}
			specs[f] = spec
		}
	} else {
		spec, err := ebpf.LoadCollectionSpec(l.objPath)
		if err != nil {
			return nil, err
		}
		specs[l.objPath] = spec
	}

	return specs, nil
}

// Close releases all eBPF resources: links, perf readers, and collections.
func (l *Loader) Close() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.connPerf != nil {
		l.connPerf.Close()
	}
	if l.httpPerf != nil {
		l.httpPerf.Close()
	}
	for _, coll := range l.collections {
		coll.Close()
	}
	close(l.events)
	l.logger.Info("eBPF loader closed", zap.Int("links_detached", len(l.links)))
}

// readConnEvents reads raw connection events from the perf buffer and converts
// them to model.ConnectionEvent values, publishing them to the events channel.
func (l *Loader) readConnEvents(ctx context.Context) {
	expectedSize := int(unsafe.Sizeof(ConnEvent{}))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := l.connPerf.Read()
		if err != nil {
			if perf.IsUnknownEvent(err) {
				continue
			}
			l.logger.Warn("conn_events perf read error", zap.Error(err))
			return
		}

		if record.LostSamples > 0 {
			l.logger.Warn("lost conn_event samples",
				zap.Uint64("count", record.LostSamples))
			continue
		}

		raw := record.RawSample
		if len(raw) < expectedSize {
			l.logger.Warn("conn_event sample too small",
				zap.Int("got", len(raw)),
				zap.Int("expected", expectedSize))
			continue
		}

		var ce ConnEvent
		ce.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
		ce.SrcIP = binary.LittleEndian.Uint32(raw[8:12])
		ce.DstIP = binary.LittleEndian.Uint32(raw[12:16])
		ce.SrcPort = binary.LittleEndian.Uint16(raw[16:18])
		ce.DstPort = binary.LittleEndian.Uint16(raw[18:20])
		ce.BytesSent = binary.LittleEndian.Uint64(raw[20:28])
		ce.BytesRecv = binary.LittleEndian.Uint64(raw[28:36])
		ce.DurationNs = binary.LittleEndian.Uint64(raw[36:44])
		ce.Retransmits = binary.LittleEndian.Uint32(raw[44:48])
		ce.Protocol = raw[48]

		evt := connEventToModel(ce)

		select {
		case l.events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

// readHTTPEvents reads raw HTTP events from the perf buffer and converts them
// to model.HTTPRequestEvent values, publishing them to the events channel.
func (l *Loader) readHTTPEvents(ctx context.Context) {
	expectedSize := int(unsafe.Sizeof(HttpEvent{}))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := l.httpPerf.Read()
		if err != nil {
			if perf.IsUnknownEvent(err) {
				continue
			}
			l.logger.Warn("http_events perf read error", zap.Error(err))
			return
		}

		if record.LostSamples > 0 {
			l.logger.Warn("lost http_event samples",
				zap.Uint64("count", record.LostSamples))
			continue
		}

		raw := record.RawSample
		if len(raw) < expectedSize {
			l.logger.Warn("http_event sample too small",
				zap.Int("got", len(raw)),
				zap.Int("expected", expectedSize))
			continue
		}

		var he HttpEvent
		he.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
		he.SrcIP = binary.LittleEndian.Uint32(raw[8:12])
		he.DstIP = binary.LittleEndian.Uint32(raw[12:16])
		he.SrcPort = binary.LittleEndian.Uint16(raw[16:18])
		he.DstPort = binary.LittleEndian.Uint16(raw[18:20])
		he.Method = raw[20]
		he.StatusCode = binary.LittleEndian.Uint16(raw[21:23])
		he.LatencyNs = binary.LittleEndian.Uint64(raw[23:31])
		copy(he.Path[:], raw[31:159])

		evt := httpEventToModel(he)

		select {
		case l.events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

// connEventToModel converts a raw ConnEvent to a model.ConnectionEvent.
func connEventToModel(ce ConnEvent) model.ConnectionEvent {
	proto := "TCP"
	if ce.Protocol == 17 {
		proto = "UDP"
	}

	return model.ConnectionEvent{
		Timestamp: time.Unix(0, int64(ce.TimestampNs)),
		Source: model.Endpoint{
			IP:   intToIPv4(ce.SrcIP),
			Port: ce.SrcPort,
		},
		Destination: model.Endpoint{
			IP:   intToIPv4(ce.DstIP),
			Port: ce.DstPort,
		},
		BytesSent:   ce.BytesSent,
		BytesRecv:   ce.BytesRecv,
		DurationNs:  ce.DurationNs,
		Retransmits: ce.Retransmits,
		Protocol:    proto,
	}
}

// httpEventToModel converts a raw HttpEvent to a model.HTTPRequestEvent.
func httpEventToModel(he HttpEvent) model.HTTPRequestEvent {
	method, ok := httpMethods[he.Method]
	if !ok {
		method = "UNKNOWN"
	}

	pathBytes := he.Path[:]
	pathLen := 0
	for i, b := range pathBytes {
		if b == 0 {
			pathLen = i
			break
		}
		pathLen = i + 1
	}
	path := string(pathBytes[:pathLen])

	return model.HTTPRequestEvent{
		Timestamp: time.Unix(0, int64(he.TimestampNs)),
		Source: model.Endpoint{
			IP:   intToIPv4(he.SrcIP),
			Port: he.SrcPort,
		},
		Destination: model.Endpoint{
			IP:   intToIPv4(he.DstIP),
			Port: he.DstPort,
		},
		Method:     method,
		Path:       path,
		StatusCode: he.StatusCode,
		LatencyNs:  he.LatencyNs,
		Protocol:   "HTTP",
	}
}

// intToIPv4 converts a uint32 (network byte order from the kernel) to a dotted
// IPv4 string.
func intToIPv4(ip uint32) string {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	).String()
}
