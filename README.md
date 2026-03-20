# nefi

**Zero-touch network observability for Kubernetes — no sidecars, no code changes, no restarts.**

nefi uses eBPF to capture service-to-service traffic at the kernel level, including TLS-encrypted payloads, and visualizes it as a real-time service topology graph.

> 한국어 문서는 [README.ko.md](README.ko.md)를 참고하세요.

---

## Motivation

As microservices scale, understanding which services talk to which becomes increasingly difficult. Common approaches each come with trade-offs:

| Approach | Trade-off |
|----------|-----------|
| Service mesh sidecars (Istio, Linkerd) | Envoy injected into every Pod — CPU/memory overhead, requires redeployment |
| Distributed tracing SDKs (Jaeger, Zipkin) | Instrumentation code must be added to every service |
| Packet capture (tcpdump, TC, XDP) | Cannot see payloads inside TLS-encrypted traffic |

nefi takes none of these approaches. By attaching eBPF probes to both kernel syscalls and TLS library functions, it **works on any existing workload with zero application changes**.

---

## Design Goals

| Goal | Description |
|------|-------------|
| **Zero-touch** | No Pod restarts. No code changes. No sidecars. Observability starts immediately. |
| **Real-time** | Events reach the dashboard within one second of occurring. |
| **Intuitive** | Service connections are shown as an interactive graph, not raw logs. |

---

## Architecture

```
┌─────────────────────────────────────────┐
│  K8s Node  (DaemonSet — one per node)   │
│                                          │
│  nefi-agent                              │
│  ├── eBPF probes (syscall + TLS uprobe) │
│  ├── K8s enrichment (PID → Pod/Service) │
│  └── gRPC streaming sender              │
└─────────────────┬───────────────────────┘
                  │ gRPC client streaming
                  ▼
┌─────────────────────────────────────────┐
│  nefi-server                            │
│  ├── gRPC CollectorService   (:9090)    │
│  ├── In-memory store (500k events)      │  ◀─ source of truth
│  │     ├── Aggregator (1s buckets)      │     for all consumers
│  │     │     └── WebSocket hub          │
│  │     └── WebSocket hub (history)      │
│  └── REST API                (:8080)    │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────────┐
       │ WebSocket           │ REST (polling)
       ▼                     ▼
  Dashboard              Topology
  (stats, 1s push)       (10s interval)
```

---

## Status

> **Alpha** — core functionality works end-to-end. APIs and data formats may change before v1.0.

### Done

- [x] **nefi-agent** (DaemonSet)
  - eBPF syscall tracepoints (`write` / `read` / `sendto` / `recvfrom`)
  - TLS uprobe — OpenSSL (`SSL_write` / `SSL_read`) and Go `crypto/tls`
  - K8s metadata enrichment: PID → Pod, IP → Pod/Service
  - gRPC client-streaming sender with exponential backoff

- [x] **nefi-server**
  - gRPC `CollectorService` receiving events from all agents
  - In-memory ring buffer (last 500k events) — single source of truth
  - Sliding-window aggregator (1s buckets, up to 5-minute window)
  - WebSocket hub: pushes aggregated stats (1s) and raw events to connected browsers
  - REST API: `GET /stats`, `GET /events`, `GET /topology`

- [x] **Web UI**
  - Dashboard: per-endpoint request count, success rate, latency — live via WebSocket (1-minute window) or REST polling (other windows)
  - Topology: interactive service graph (cytoscape.js + dagre), color-coded by success rate — refreshed every 10s via REST
  - Settings: 6 themes, node/edge visual customization

- [x] **Kubernetes manifests** — DaemonSet + Deployment YAML
- [x] **Multi-arch Docker images** — `linux/amd64` and `linux/arm64`

### Roadmap

- [ ] Persistent storage (server restart currently loses all data)
- [ ] Alerting — configurable thresholds on success rate or latency
- [ ] Multi-cluster support
- [ ] Dashboard authentication
- [ ] Helm chart
- [ ] Struct layout validation — automated check that `DataEvent` (Go) and `data_event_t` (C) field order and sizes match at build time, to catch silent misreads caused by any layout drift

---

## Requirements

- Linux kernel **5.8+** (BPF ring buffer required)
- Kubernetes **1.24+**
- Privileged DaemonSet pods with `hostPID` and `hostNetwork`
- `/sys/kernel/debug` mounted on nodes

> Tested on k3s v1.34, `arm64` and `amd64`.

---

## Getting Started

### Deploy

```bash
# 1. Deploy the server
kubectl apply -f deploy/server-deployment.yaml

# 2. Deploy the agent on all nodes
kubectl apply -f deploy/agent-daemonset.yaml

# 3. Open the dashboard
kubectl port-forward -n nefi svc/nefi-server 8080:8080
# → http://localhost:8080
```

To deploy the agent on specific nodes only:

```bash
make agent-enable-node NODE=<node-name>
```

### Build from source

> Requires Docker with `buildx`, and a Linux host (or CI) for compiling the eBPF programs (`clang`, `libbpf-dev`, `libelf-dev`).

```bash
# Build and push the server image (includes UI build)
make server-deploy

# Build and push the agent image
make agent-deploy
```

The default registry is `ghcr.io/gihongjo`. Override it with:

```bash
make server-deploy REGISTRY=<your-registry>
make agent-deploy  REGISTRY=<your-registry>
```

Run `make help` to see all available targets.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request to discuss the change.

- **Bug reports**: include kernel version, architecture, and a description of the observed vs. expected behavior.
- **Feature requests**: describe the use case and what problem it solves.

---

## License

[MIT](LICENSE)
