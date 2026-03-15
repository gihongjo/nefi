//go:build !linux

package ebpf

import (
	"fmt"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
)

// SSLLoader is a no-op stub on non-Linux platforms.
type SSLLoader struct{}

// NewSSLLoader always returns an error on non-Linux platforms.
func NewSSLLoader(_ *ciliumebpf.Map) (*SSLLoader, error) {
	return nil, fmt.Errorf("SSL tracing requires Linux")
}

// Close is a no-op.
func (s *SSLLoader) Close() {}

// ProcScanner is a no-op stub on non-Linux platforms.
type ProcScanner struct{}

// NewProcScanner returns a no-op scanner.
func NewProcScanner(_ *SSLLoader, _ time.Duration) *ProcScanner {
	return &ProcScanner{}
}

// Start is a no-op.
func (p *ProcScanner) Start() {}

// Stop is a no-op.
func (p *ProcScanner) Stop() {}
