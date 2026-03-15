// Package ebpf는 BPF 프로그램의 로드, tracepoint attach, 이벤트 읽기를 담당한다.
//
// 역할 (loader.go):
//   nefi_trace.c를 컴파일한 BPF 오브젝트를 커널에 로드하고,
//   syscall tracepoint에 attach한 뒤 ringbuf에서 이벤트를 읽어 반환한다.
//
// 흐름:
//   1. New() 호출
//      → loadNefiTraceObjects(): BPF .o 파일을 커널에 로드
//      → attach(): 각 syscall tracepoint에 BPF 프로그램 연결
//         - connect/accept4  : 소켓 FD를 socket_fds 맵에 등록
//         - write/read       : socket_fds에 있는 FD만 페이로드 캡처
//         - sendto/recvfrom  : 자동 FD 등록 + 페이로드 캡처
//         - close            : socket_fds 및 conn_state 정리
//      → ringbuf.NewReader(): 커널 ringbuf 구독 시작
//
//   2. Read() 반복 호출 (main.go의 루프에서)
//      → 커널이 이벤트를 ringbuf에 쓸 때까지 블로킹
//      → 바이너리 데이터를 model.DataEvent 구조체로 역직렬화해서 반환
//
//   3. EventsMap()
//      → ssl_loader.go(SSLLoader)가 같은 ringbuf를 공유하기 위해 맵을 가져감
//         (uprobe 이벤트와 tracepoint 이벤트가 같은 루프에서 처리됨)
//
// 생성 파일 (go generate로 자동 생성, 커밋됨):
//   nefitrace_arm64_bpfel.go  — arm64용 BPF 오브젝트 Go 래퍼
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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall" nefiTrace ../../../bpf/nefi_trace.c

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
		{"syscalls", "sys_enter_accept4", l.objs.TpSysEnterAccept4},
		{"syscalls", "sys_exit_accept4", l.objs.TpSysExitAccept4},
		{"syscalls", "sys_enter_accept", l.objs.TpSysEnterAccept},
		{"syscalls", "sys_exit_accept", l.objs.TpSysExitAccept},
		{"syscalls", "sys_enter_write", l.objs.TpSysEnterWrite},
		{"syscalls", "sys_exit_write", l.objs.TpSysExitWrite},
		{"syscalls", "sys_enter_read", l.objs.TpSysEnterRead},
		{"syscalls", "sys_exit_read", l.objs.TpSysExitRead},
		{"syscalls", "sys_enter_sendto", l.objs.TpSysEnterSendto},
		{"syscalls", "sys_exit_sendto", l.objs.TpSysExitSendto},
		{"syscalls", "sys_enter_recvfrom", l.objs.TpSysEnterRecvfrom},
		{"syscalls", "sys_exit_recvfrom", l.objs.TpSysExitRecvfrom},
		// recvmsg: Java NIO (Tomcat/Spring Boot) may use this instead of read()
		{"syscalls", "sys_enter_recvmsg", l.objs.TpSysEnterRecvmsg},
		{"syscalls", "sys_exit_recvmsg", l.objs.TpSysExitRecvmsg},
		// readv: scatter-gather read used by some Java NIO implementations
		{"syscalls", "sys_enter_readv", l.objs.TpSysEnterReadv},
		{"syscalls", "sys_exit_readv", l.objs.TpSysExitReadv},
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

// EventsMap returns the shared ring buffer map so that SSLLoader can route
// uprobe events into the same reader loop as the tracepoint events.
func (l *Loader) EventsMap() *ciliumebpf.Map {
	return l.objs.Events
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
