# CLAUDE.md

I want to build a Kubernetes tool that combines the functionality of Kiali and Jaeger, plus more features, using Istio ambient mode's ztunnel. I want to create a tool that visualizes API flows within Kubernetes, as well as visualizes outages, response times, and more.
I speak English, but you must respond in English.


This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This workspace (`nephilia`) contains cloned git repositories for Istio ecosystem projects used for development and contribution:

- **`ztunnel_git/ztunnel/`** — Istio's ambient mesh node proxy (Rust). Provides transparent L4 proxying via HBONE (HTTP/2 tunneling).
- **`jaeger_git/jaeger/`** — CNCF distributed tracing platform (Go). Jaeger v2 is built on OpenTelemetry Collector architecture.
- **`istio_git/`** — Placeholder for Istio control plane (currently empty).

---

## Ztunnel (Rust)

### Build & Test Commands

```bash
cd ztunnel_git/ztunnel

# Build
cargo build                          # Debug build (default: tls-aws-lc)
cargo build --profile quick-release  # Fast release (no LTO, 16 codegen units)
cargo build --release                # Full release (LTO, opt-level=3)

# Test
make test                            # Tests with RUST_BACKTRACE=1
cargo test                           # Standard test run
cargo test <test_name>               # Single test

# Lint & Format
make lint                            # Clippy + copyright/yaml/markdown/license checks
make fix                             # Auto-fix clippy + rustfmt
cargo clippy                         # Clippy only

# Pre-submit (required before PR)
make presubmit                       # check-features + test + lint + gen-check

# Feature variants
cargo build -F tls-ring              # Ring crypto backend
cargo build -F tls-boring            # BoringSSL (FIPS)
cargo build -F tls-openssl           # OpenSSL backend
make check-features                  # Verify all TLS variants compile

# Other
make coverage                        # Test coverage report
make cve-check                       # cargo deny advisories
make license-check                   # cargo deny licenses
```

### Architecture

**Dual Tokio Runtime Model:**
- **Main thread** (single-threaded): Admin server, XDS client, readiness — control plane concerns.
- **Worker threads** (multi-threaded, default 2): All data plane traffic proxying.

**Proxying Modes:**
- **Dedicated mode** (`PROXY_MODE=dedicated`): One proxy per workload. Recommended for local dev.
- **Shared mode** (`PROXY_MODE=shared`, Linux only): Multiple workloads per ztunnel instance using network namespaces. Production default.

**Traffic Flow:**
Pod traffic is captured via iptables → ztunnel listeners (ports 15001/15006/15080) → RBAC policy check → mTLS HBONE tunnel (H2 on port 15008) → upstream ztunnel → destination app.

**Key Port Assignments:**
| Port | Purpose |
|-------|---------|
| 15001 | Outbound traffic capture |
| 15006 | Inbound plaintext capture |
| 15008 | Inbound HBONE (H2 mTLS) |
| 15080 | SOCKS5 outbound (unstable) |
| 15053 | DNS proxy |
| 15000 | Admin (localhost only) |
| 15020 | Prometheus metrics |
| 15021 | Readiness probe |

**Source Layout (`src/`):**
- `proxy/` — Core proxy: inbound, outbound, H2 client/server, connection pooling, SOCKS5
- `state/` — Workload, service, and policy state models (RwLock-based, XDS-driven)
- `xds/` — Envoy xDS client for config updates from Istiod
- `identity/` + `tls/` + `rbac/` — mTLS identity, certificate management, RBAC enforcement
- `dns/` — DNS proxy with caching and upstream forwarding
- `inpod/` (Linux only) — Shared-mode per-workload proxy lifecycle, netns handling
- `copy/` — Zero-copy bidirectional I/O with dynamic buffer sizing (1KB→16KB→256KB)
- `config/` — All config via environment variables (see `PROXY_MODE`, `XDS_ADDRESS`, `FAKE_CA`, etc.)

**Build-time codegen:** `build.rs` compiles 5 proto files (xds, workload, authorization, citadel, zds) via tonic/prost and extracts build info from `common/scripts/report_build_info.sh`.

**Rust edition:** 2024. Minimum Rust version: 1.90.

---

## Jaeger (Go)

### Build & Test Commands

```bash
cd jaeger_git/jaeger

# Setup (first time)
git submodule update --init --recursive
make install-tools

# Build
make build-jaeger                    # Main jaeger v2 binary
go run ./cmd/jaeger --config ./cmd/jaeger/config.yaml  # Run locally

# Test
make test                            # All tests with race detector
make cover                           # Coverage report (95% target)
go test ./internal/storage/...       # Test specific package
go test -run TestName ./pkg/...      # Single test

# Lint & Format
make fmt                             # gofumpt + import ordering + license headers
make lint                            # All linters (golangci-lint, goroutine leaks, etc.)
make lint-go                         # golangci-lint only

# Other
make build-ui                       # Build and embed UI assets
make build-all-platforms            # Cross-platform builds
make nocover                       # Verify all packages have tests
```

### Architecture

**OTel Collector-Based (v2):** Jaeger v2 runs as an OpenTelemetry Collector distribution with custom extensions. The main binary (`cmd/jaeger/`) bundles collector, query, and storage into one process.

**Custom OTel Extensions** (`cmd/jaeger/internal/extension/`):
- `jaegerstorage` — Storage factory (Cassandra, Elasticsearch, Badger, ClickHouse, memory, gRPC)
- `jaegerquery` — Query service with embedded React UI (port 16686)
- `jaegermcp` — Model Context Protocol for LLM integration
- `remotesampling` — Adaptive sampling strategies
- `remotestorage` — Remote storage plugin interface

**Storage Layer** (`internal/storage/`):
- **v1 API** (`v1/api/`): SpanStore, DependencyStore, SamplingStore interfaces
- **v2 API** (`v2/api/`): TraceStore, DepStore — newer gRPC-based interfaces
- **v1adapter** (`v2/v1adapter/`): Converts v1 backends to v2 API
- Implementations: badger, cassandra, elasticsearch, clickhouse, grpc, memory

**Key Patterns:**
- Factory pattern for storage backends
- Interface-based design throughout (all storage is pluggable)
- Viper/Cobra for configuration and CLI
- 95% minimum code coverage enforced; all packages must have `*_test.go` files
- Go 1.24.6+, CGO_ENABLED=0 for static builds

**Do Not Edit (auto-generated):**
- `*.pb.go`, `*_mock.go`, `internal/proto-gen/`
- `jaeger-ui/` and `idl/` are git submodules (PRs go to their respective repos)

**Key Ports (all-in-one mode):**
| Port | Purpose |
|-------|---------|
| 16686 | Query HTTP (UI) |
| 16685 | Query gRPC |
| 4317 | OTLP gRPC |
| 4318 | OTLP HTTP |
| 14268 | Jaeger Thrift HTTP |
| 5778 | Remote sampling HTTP |

**Contributing:** Commits must be signed (`git commit -s`). Run `make fmt && make lint && make test` before PRs. New contributors have PR limits (1 open PR until first merge).
