# nefi

**사이드카 없이, 코드 수정 없이, 재시작 없이 — Kubernetes 서비스 간 트래픽을 실시간으로 관측하는 도구**

nefi는 eBPF를 이용해 TLS 암호화 트래픽을 포함한 서비스 간 통신을 커널 레벨에서 캡처하고, 이를 실시간 서비스 토폴로지 그래프로 시각화합니다.

> English documentation: [README.md](README.md)

---

## 배경

마이크로서비스가 많아질수록 "지금 어떤 서비스가 어떤 서비스와 통신하는지" 파악하기가 어려워집니다. 기존 방법들은 각자 한계가 있습니다.

| 방법 | 한계 |
|------|------|
| 서비스 메시 사이드카 (Istio, Linkerd) | 모든 Pod에 Envoy 주입 필요 — 오버헤드 발생, 기존 애플리케이션 재배포 필수 |
| 분산 추적 SDK (Jaeger, Zipkin) | 모든 서비스에 계측 코드를 직접 삽입해야 함 |
| 패킷 캡처 (tcpdump, TC, XDP) | TLS로 암호화된 트래픽에서 페이로드를 볼 수 없음 |

nefi는 이 세 가지를 모두 쓰지 않습니다. 커널 syscall과 TLS 라이브러리 함수에 직접 eBPF 프로브를 붙이기 때문에, **기존 워크로드를 건드리지 않고 즉시 관측을 시작**할 수 있습니다.

---

## 설계 목표

| 목표 | 설명 |
|------|------|
| **Zero-touch** | Pod 재시작 없이, 코드 수정 없이, 사이드카 없이 즉시 관측 시작 |
| **실시간** | 이벤트 발생 후 1초 이내에 대시보드에 반영 |
| **직관적 시각화** | 원시 로그 대신, 서비스 연결 구조를 인터랙티브 그래프로 표시 |

---

## 아키텍처

```
┌─────────────────────────────────────────┐
│  K8s 노드  (DaemonSet — 노드당 1개)     │
│                                          │
│  nefi-agent                              │
│  ├── eBPF 프로브 (syscall + TLS uprobe) │
│  ├── K8s enrichment (PID → Pod/Service) │
│  └── gRPC 스트리밍 전송                  │
└─────────────────┬───────────────────────┘
                  │ gRPC client streaming
                  ▼
┌─────────────────────────────────────────┐
│  nefi-server                            │
│  ├── gRPC CollectorService   (:9090)    │
│  ├── 인메모리 스토어 (최근 50만 이벤트)  │  ◀─ 모든 소비자의 단일 원본
│  │     ├── Aggregator (1초 단위 버킷)   │
│  │     │     └── WebSocket 허브         │
│  │     └── WebSocket 허브 (히스토리)    │
│  └── REST API                (:8080)    │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────────┐
       │ WebSocket           │ REST (폴링)
       ▼                     ▼
  Dashboard              Topology
  (통계, 1초 push)        (10초 간격)
```

---

## 현재 상태

> **Alpha** — 핵심 기능은 동작합니다. v1.0 이전에 API와 데이터 형식이 변경될 수 있습니다.

### 구현 완료

- [x] **nefi-agent** (DaemonSet)
  - eBPF syscall tracepoint (`write` / `read` / `sendto` / `recvfrom`)
  - TLS uprobe — OpenSSL (`SSL_write` / `SSL_read`) 및 Go `crypto/tls`
  - K8s 메타데이터 enrichment: PID → Pod, IP → Pod/Service
  - 지수 백오프 적용된 gRPC client-streaming 전송

- [x] **nefi-server**
  - 모든 에이전트로부터 이벤트를 수신하는 gRPC `CollectorService`
  - 인메모리 링 버퍼 스토어 (최근 50만 이벤트) — 모든 소비자의 단일 원본
  - 슬라이딩 윈도우 집계기 (1초 단위 버킷, 최대 5분)
  - WebSocket 허브: 집계 통계(1초)와 raw 이벤트를 연결된 브라우저에 전송
  - REST API: `GET /stats`, `GET /events`, `GET /topology`

- [x] **Web UI**
  - Dashboard: 엔드포인트별 요청 수·성공률·레이턴시 — WebSocket 실시간(1분 윈도우) 또는 REST 폴링(그 외 윈도우)
  - Topology: 성공률에 따라 색상이 변하는 인터랙티브 서비스 그래프 (cytoscape.js + dagre) — REST 10초 폴링
  - Settings: 6가지 테마, 노드/엣지 시각화 커스터마이징

- [x] **Kubernetes 배포 파일** — DaemonSet + Deployment YAML
- [x] **멀티 아키텍처 Docker 이미지** — `linux/amd64` 및 `linux/arm64`

### 로드맵

- [ ] 영구 저장소 연동 (현재 서버 재시작 시 데이터 초기화)
- [ ] 알림 기능 — 성공률·레이턴시 임계값 기반 알림
- [ ] 멀티 클러스터 지원
- [ ] 대시보드 인증
- [ ] Helm chart
- [ ] 구조체 레이아웃 검증 — `DataEvent` (Go)와 `data_event_t` (C)의 필드 순서·크기 일치 여부를 빌드 타임에 자동으로 검사하는 장치 (레이아웃 불일치로 인한 묵시적 오독 방지)

---

## 요구 사항

- Linux 커널 **5.8+** (BPF ring buffer 지원 필요)
- Kubernetes **1.24+**
- `privileged` 권한이 있는 DaemonSet Pod (`hostPID`, `hostNetwork` 필요)
- 노드에 `/sys/kernel/debug` 마운트

> k3s v1.34, `arm64` 및 `amd64`에서 동작 확인.

---

## 시작하기

### 배포

```bash
# 1. 서버 배포
kubectl apply -f deploy/server-deployment.yaml

# 2. 전체 노드에 에이전트 배포
kubectl apply -f deploy/agent-daemonset.yaml

# 3. 대시보드 열기
kubectl port-forward -n nefi svc/nefi-server 8080:8080
# → http://localhost:8080
```

특정 노드에만 에이전트를 배포하려면:

```bash
make agent-enable-node NODE=<노드-이름>
```

### 소스에서 빌드

> Docker `buildx`와 eBPF 프로그램 컴파일을 위한 Linux 환경(`clang`, `libbpf-dev`, `libelf-dev`)이 필요합니다.

```bash
# 서버 이미지 빌드 및 배포 (UI 빌드 포함)
make server-deploy

# 에이전트 이미지 빌드 및 배포
make agent-deploy
```

기본 레지스트리는 `ghcr.io/gihongjo`입니다. 변경하려면:

```bash
make server-deploy REGISTRY=<사용할-레지스트리>
make agent-deploy  REGISTRY=<사용할-레지스트리>
```

전체 타겟 목록은 `make help`로 확인하세요.

---

## 기여

기여는 언제나 환영합니다. PR을 보내기 전에 먼저 이슈를 열어 변경 사항을 논의해 주세요.

- **버그 리포트**: 커널 버전, 아키텍처, 발생 현상과 예상 동작을 함께 기재해 주세요.
- **기능 제안**: 해결하고자 하는 문제와 사용 사례를 설명해 주세요.

---

## 라이선스

[MIT](LICENSE)
