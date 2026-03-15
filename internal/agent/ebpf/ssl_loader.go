//go:build linux

// ssl_loader.go — SSL/TLS uprobe 관리 (Linux 전용)
//
// 역할:
//   OpenSSL(libssl.so)과 Go 표준 라이브러리(crypto/tls)의 암호화 함수에
//   uprobe를 걸어서 syscall 레벨에서는 볼 수 없는 평문 데이터를 캡처한다.
//
// 왜 필요한가:
//   HTTPS처럼 TLS로 암호화된 트래픽은 write() syscall에 도달할 때
//   이미 암호화된 상태다. nefi_trace.c의 tracepoint만으로는 평문을 볼 수 없어서
//   암호화가 일어나기 직전의 라이브러리 함수(SSL_write, crypto/tls Write)에
//   uprobe를 걸어 평문을 가로챈다.
//
// 구성 요소:
//
//   SSLLoader
//     - ssl_trace.c BPF 프로그램을 로드한다.
//     - loader.go의 ringbuf를 공유(MapReplacements)해서 uprobe 이벤트도
//       같은 Read() 루프에서 처리된다.
//     - AttachOpenSSL(path): libssl.so에 SSL_write/SSL_read uprobe 연결
//     - AttachGoTLS(path, writeOff, readOff): Go 바이너리에 파일 오프셋 기반 uprobe 연결
//
//   ProcScanner
//     - 5초마다 /proc 디렉토리를 순회하며 새로운 프로세스를 감지한다.
//     - /proc/<pid>/maps → "libssl" 포함 줄 → AttachOpenSSL()
//     - /proc/<pid>/exe  → Go 바이너리 감지 → findGoTLSOffsets() → AttachGoTLS()
//     - 이미 처리한 경로는 seenSSL/seenGoTLS 맵으로 중복 처리를 방지한다.
//     - 에이전트 시작 후 새로 뜨는 프로세스도 커버하기 위해 주기적으로 실행한다.
//
//   findGoTLSOffsets(path)
//     - Go 바이너리의 ELF .symtab에서 crypto/tls.(*Conn).Write / .Read 심볼을 찾는다.
//     - ELF 가상 주소(VA)를 uprobe에 필요한 파일 오프셋으로 변환한다.
//     - stripped 바이너리(심볼 테이블 없음)이면 에러를 반환하고 조용히 skip된다.
//
// 한계:
//   stripped Go 바이너리는 .symtab이 없어 crypto/tls 심볼을 찾지 못한다.
//   (해결 방향: pclntab 파싱으로 대체)

package ebpf

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cc clang -cflags "-O2 -g -Wall" sslTrace ../../../bpf/ssl_trace.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall" sslTrace ../../../bpf/ssl_trace.c

// SSLLoader loads the SSL/TLS uprobe BPF programs and manages per-executable
// attachments. The shared events ring buffer is passed in from the main Loader
// so both uprobe and tracepoint events flow through the same reader loop.
type SSLLoader struct {
	objs      sslTraceObjects
	links     []link.Link
	mu        sync.Mutex
	seenSSL   map[string]bool // libssl.so paths already attached
	seenGoTLS map[string]bool // Go binary paths already attached
}

// NewSSLLoader initialises the SSL uprobe BPF programs, replacing the
// placeholder `events` ring buffer with the one shared by the main Loader.
func NewSSLLoader(sharedEvents *ciliumebpf.Map) (*SSLLoader, error) {
	opts := &ciliumebpf.CollectionOptions{
		MapReplacements: map[string]*ciliumebpf.Map{
			"events": sharedEvents,
		},
	}

	l := &SSLLoader{
		seenSSL:   make(map[string]bool),
		seenGoTLS: make(map[string]bool),
	}

	if err := loadSslTraceObjects(&l.objs, opts); err != nil {
		return nil, fmt.Errorf("loading SSL BPF objects: %w", err)
	}

	return l, nil
}

// AttachOpenSSL attaches SSL_write / SSL_read uprobe+uretprobe to libssl at
// libsslPath. Calls for the same path are silently deduplicated.
func (s *SSLLoader) AttachOpenSSL(libsslPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seenSSL[libsslPath] {
		return nil
	}
	// Mark as seen immediately so failures are not retried on every scan.
	s.seenSSL[libsslPath] = true

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", libsslPath, err)
	}

	// Collect new links; on any error roll them back before returning.
	var newLinks []link.Link
	rollback := func() {
		for _, l := range newLinks {
			l.Close()
		}
	}

	wEntry, err := ex.Uprobe("SSL_write", s.objs.UprobeSslWriteEntry, nil)
	if err != nil {
		return fmt.Errorf("uprobe SSL_write: %w", err)
	}
	newLinks = append(newLinks, wEntry)

	wRet, err := ex.Uretprobe("SSL_write", s.objs.UretprobeSslWrite, nil)
	if err != nil {
		rollback()
		return fmt.Errorf("uretprobe SSL_write: %w", err)
	}
	newLinks = append(newLinks, wRet)

	rEntry, err := ex.Uprobe("SSL_read", s.objs.UprobeSslReadEntry, nil)
	if err != nil {
		rollback()
		return fmt.Errorf("uprobe SSL_read: %w", err)
	}
	newLinks = append(newLinks, rEntry)

	rRet, err := ex.Uretprobe("SSL_read", s.objs.UretprobeSslRead, nil)
	if err != nil {
		rollback()
		return fmt.Errorf("uretprobe SSL_read: %w", err)
	}
	newLinks = append(newLinks, rRet)

	s.links = append(s.links, newLinks...)
	log.Printf("[SSL] attached OpenSSL uprobe: %s", libsslPath)
	return nil
}

// AttachGoTLS attaches crypto/tls.(*Conn).Write and .Read uprobes to a Go
// binary using file offsets obtained from findGoTLSOffsets.
//
// Write: entry probe only (plaintext buffer is available at entry).
// Read:  entry probe + one uprobe per RET instruction (instead of uretprobe,
//        which crashes Go's runtime by patching the goroutine return address).
func (s *SSLLoader) AttachGoTLS(exePath string, writeOff, readOff uint64, readRetOffs []uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", exePath, err)
	}

	var newLinks []link.Link
	rollback := func() {
		for _, l := range newLinks {
			l.Close()
		}
	}

	// Write — entry probe only.
	wEntry, err := ex.Uprobe("", s.objs.UprobeGoTlsWriteEntry,
		&link.UprobeOptions{Address: writeOff})
	if err != nil {
		return fmt.Errorf("uprobe go_tls_write entry (off=0x%x): %w", writeOff, err)
	}
	newLinks = append(newLinks, wEntry)

	// Read — entry probe.
	rEntry, err := ex.Uprobe("", s.objs.UprobeGoTlsReadEntry,
		&link.UprobeOptions{Address: readOff})
	if err != nil {
		rollback()
		return fmt.Errorf("uprobe go_tls_read entry (off=0x%x): %w", readOff, err)
	}
	newLinks = append(newLinks, rEntry)

	// Read — one uprobe per RET instruction (safe alternative to uretprobe).
	for _, retOff := range readRetOffs {
		rRet, err := ex.Uprobe("", s.objs.UprobeGoTlsReadRet,
			&link.UprobeOptions{Address: retOff})
		if err != nil {
			rollback()
			return fmt.Errorf("uprobe go_tls_read ret (off=0x%x): %w", retOff, err)
		}
		newLinks = append(newLinks, rRet)
	}

	s.links = append(s.links, newLinks...)
	log.Printf("[SSL] attached Go TLS uprobe: %s (write=0x%x read=0x%x, %d ret probes)",
		exePath, writeOff, readOff, len(readRetOffs))
	return nil
}

// isGoTLSSeen reports whether exePath has already been processed without
// requiring the caller to hold the lock.
func (s *SSLLoader) isGoTLSSeen(exePath string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seenGoTLS[exePath]
}

// markGoTLSSeen marks exePath as processed so it is not retried on future scans.
func (s *SSLLoader) markGoTLSSeen(exePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seenGoTLS[exePath] = true
}

// Close releases all uprobe links and BPF objects.
func (s *SSLLoader) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, lnk := range s.links {
		lnk.Close()
	}
	s.objs.Close()
}

// ─── ProcScanner ────────────────────────────────────────────────

// ProcScanner periodically walks /proc to discover new libssl.so and Go
// binary instances, then attaches the corresponding uprobes via SSLLoader.
type ProcScanner struct {
	loader   *SSLLoader
	interval time.Duration
	stopCh   chan struct{}
}

// NewProcScanner creates a scanner that calls loader every interval.
func NewProcScanner(l *SSLLoader, interval time.Duration) *ProcScanner {
	return &ProcScanner{
		loader:   l,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start launches the background scan goroutine (non-blocking).
func (p *ProcScanner) Start() {
	go p.run()
}

// Stop signals the background goroutine to exit.
func (p *ProcScanner) Stop() {
	close(p.stopCh)
}

func (p *ProcScanner) run() {
	// Run immediately on start, then on every tick.
	p.scan()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.scan()
		case <-p.stopCh:
			return
		}
	}
}

func (p *ProcScanner) scan() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	selfPID := fmt.Sprintf("%d", os.Getpid())
	for _, e := range entries {
		if !isNumericDir(e.Name()) {
			continue
		}
		// Skip our own process to avoid attaching uprobes to nefi-agent itself.
		// Doing so would cause recursive ringbuf writes (k8s client TLS calls
		// trigger the uprobe which tries to emit events) and crash the process.
		if e.Name() == selfPID {
			continue
		}
		pid := e.Name()
		p.scanMapsForSSL(pid)
		p.scanExeForGoTLS(pid)
	}
}

// scanMapsForSSL reads /proc/<pid>/maps and attaches to any libssl.so path
// that has not yet been seen.
func (p *ProcScanner) scanMapsForSSL(pid string) {
	f, err := os.Open("/proc/" + pid + "/maps")
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "libssl") {
			continue
		}
		// /proc/pid/maps fields: addr perms offset dev inode pathname
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[5]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			// File doesn't exist on this node — mark seen and skip silently.
			p.loader.mu.Lock()
			p.loader.seenSSL[path] = true
			p.loader.mu.Unlock()
			continue
		}
		if err := p.loader.AttachOpenSSL(path); err != nil {
			log.Printf("[SSL] AttachOpenSSL %s: %v", path, err)
		}
	}
}

// scanExeForGoTLS reads /proc/<pid>/exe, attempts ELF symbol lookup for
// crypto/tls symbols, and attaches uprobes if found.
func (p *ProcScanner) scanExeForGoTLS(pid string) {
	exePath, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil {
		return
	}

	// Fast path: already processed this binary (success or failure).
	if p.loader.isGoTLSSeen(exePath) {
		return
	}

	// Mark as seen immediately so failed binaries are not retried on every scan.
	p.loader.markGoTLSSeen(exePath)

	writeOff, readOff, readRetOffs, err := findGoTLSOffsets(exePath)
	if err != nil {
		// Not a Go binary, stripped, or doesn't use crypto/tls — skip silently.
		return
	}

	if err := p.loader.AttachGoTLS(exePath, writeOff, readOff, readRetOffs); err != nil {
		log.Printf("[SSL] AttachGoTLS %s: %v", exePath, err)
	}
}

func isNumericDir(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ─── ELF symbol helpers ──────────────────────────────────────────

// findGoTLSOffsets opens a Go ELF binary and returns:
//   - writeOff: file offset of crypto/tls.(*Conn).Write entry
//   - readOff:  file offset of crypto/tls.(*Conn).Read entry
//   - readRetOffs: file offsets of every RET instruction inside Read
//     (used to attach uprobe at each return point instead of uretprobe,
//      avoiding the Go copystack crash caused by uretprobe's stack patching)
func findGoTLSOffsets(path string) (writeOff, readOff uint64, readRetOffs []uint64, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0, nil, err
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("no symbol table in %s: %w", path, err)
	}

	var writeVA, readVA, readSize uint64
	for _, sym := range syms {
		switch sym.Name {
		case "crypto/tls.(*Conn).Write":
			writeVA = sym.Value
		case "crypto/tls.(*Conn).Read":
			readVA = sym.Value
			readSize = sym.Size
		}
		if writeVA != 0 && readVA != 0 {
			break
		}
	}

	if writeVA == 0 || readVA == 0 {
		return 0, 0, nil, fmt.Errorf("crypto/tls symbols not found in %s", path)
	}

	writeOff, err = vaToFileOffset(f, writeVA)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("write VA 0x%x → file offset: %w", writeVA, err)
	}
	readOff, err = vaToFileOffset(f, readVA)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("read VA 0x%x → file offset: %w", readVA, err)
	}

	readRetOffs, err = findRetOffsets(path, readOff, readSize, f.Machine)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("read RET offsets: %w", err)
	}

	return writeOff, readOff, readRetOffs, nil
}

// findRetOffsets reads the function body at startOff (file offset) of the
// given size and returns the file offsets of every RET instruction.
// Supports arm64 (fixed 4-byte encoding) and amd64 (0xC3).
func findRetOffsets(path string, startOff, size uint64, arch elf.Machine) ([]uint64, error) {
	if size == 0 {
		return nil, fmt.Errorf("function size is 0")
	}

	rawFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer rawFile.Close()

	buf := make([]byte, size)
	n, err := rawFile.ReadAt(buf, int64(startOff))
	if err != nil && n == 0 {
		return nil, fmt.Errorf("reading function body: %w", err)
	}
	buf = buf[:n]

	var retOffs []uint64
	switch arch {
	case elf.EM_AARCH64:
		// RET instruction encoding (little-endian): C0 03 5F D6
		for i := 0; i+4 <= len(buf); i += 4 {
			if buf[i] == 0xC0 && buf[i+1] == 0x03 && buf[i+2] == 0x5F && buf[i+3] == 0xD6 {
				retOffs = append(retOffs, startOff+uint64(i))
			}
		}
	case elf.EM_X86_64:
		// RET (near return): 0xC3
		for i := 0; i < len(buf); i++ {
			if buf[i] == 0xC3 {
				retOffs = append(retOffs, startOff+uint64(i))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported architecture: %v", arch)
	}

	if len(retOffs) == 0 {
		return nil, fmt.Errorf("no RET instructions found in function body")
	}
	return retOffs, nil
}

// vaToFileOffset converts an ELF virtual address to a file offset by
// walking the PT_LOAD program headers.
func vaToFileOffset(f *elf.File, va uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if va >= prog.Vaddr && va < prog.Vaddr+prog.Filesz {
			return (va - prog.Vaddr) + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("VA 0x%x not in any PT_LOAD segment", va)
}
