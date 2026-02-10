package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/gihongjo/nefi/internal/model"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cc clang -cflags "-O2 -g -Wall" nefiTrace ../../../bpf/nefi_trace.c

// AMD64 로 배포 시.
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall" nefiTrace ../../../bpf/nefi_trace.c

// Loader manages the BPF program lifecycle: load, attach, read events.
type Loader struct {
	objs   nefiTraceObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New loads the BPF objects, attaches tracepoints, and opens the ring buffer.
func New() (*Loader, error) {
	var objs nefiTraceObjects
	if err := loadNefiTraceObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	l := &Loader{objs: objs}

	if err := l.attach(); err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tracepoints: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	l.reader = reader

	return l, nil
}

// attach hooks all BPF programs to their respective tracepoints.
func (l *Loader) attach() error {
	type entry struct {
		group string
		name  string
		prog  *ciliumebpf.Program
	}

	// bpf2go generates program fields named in PascalCase from C function names.
	// e.g. tp_sys_enter_connect -> TpSysEnterConnect
	entries := []entry{
		{"syscalls", "sys_enter_connect", l.objs.TpSysEnterConnect},
		{"syscalls", "sys_exit_accept4", l.objs.TpSysExitAccept4},
		{"syscalls", "sys_enter_write", l.objs.TpSysEnterWrite},
		{"syscalls", "sys_exit_write", l.objs.TpSysExitWrite},
		{"syscalls", "sys_enter_read", l.objs.TpSysEnterRead},
		{"syscalls", "sys_exit_read", l.objs.TpSysExitRead},
		{"syscalls", "sys_enter_sendto", l.objs.TpSysEnterSendto},
		{"syscalls", "sys_exit_sendto", l.objs.TpSysExitSendto},
		{"syscalls", "sys_enter_recvfrom", l.objs.TpSysEnterRecvfrom},
		{"syscalls", "sys_exit_recvfrom", l.objs.TpSysExitRecvfrom},
		{"syscalls", "sys_enter_close", l.objs.TpSysEnterClose},
	}

	for _, e := range entries {
		lnk, err := link.Tracepoint(e.group, e.name, e.prog, nil)
		if err != nil {
			for _, prev := range l.links {
				prev.Close()
			}
			return fmt.Errorf("tracepoint %s/%s: %w", e.group, e.name, err)
		}
		l.links = append(l.links, lnk)
	}

	return nil
}

// Read blocks until the next event is available and returns it.
func (l *Loader) Read() (*model.DataEvent, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("reading ring buffer: %w", err)
	}

	var event model.DataEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parsing event: %w", err)
	}
	return &event, nil
}

// Close releases all BPF resources.
func (l *Loader) Close() {
	if l.reader != nil {
		l.reader.Close()
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.objs.Close()
}
