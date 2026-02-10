# Nefi - 어떻게 동작하는가

Nefi는 Kubernetes 클러스터 안의 **모든 네트워크 트래픽을 커널 레벨에서 잡아내서**, 서비스 간 관계와 성능 지표를 시각화하는 도구입니다.

```
┌──────────────────────────────────────────────────────────────────┐
│  Linux Kernel                                                    │
│                                                                  │
│  App이 TCP/UDP 통신 → 커널 함수 호출됨 → eBPF가 여기 붙어서 감청 │
└───────────────┬──────────────────────────────────────────────────┘
                │ perf buffer (커널 → 유저스페이스 통로)
                ▼
┌──────────────────────────────┐
│  nefi-agent (Go, DaemonSet)  │  ← 모든 노드에 1개씩 배포
│  - eBPF 이벤트 수신          │
│  - K8s 메타데이터 붙이기     │
│  - gRPC로 서버에 전송        │
└───────────────┬──────────────┘
                │ gRPC stream
                ▼
┌──────────────────────────────┐
│  nefi-server (Go, Deployment)│
│  - 이벤트 수신 & 저장        │
│  - 의존성 그래프 계산        │
│  - 메트릭 집계 (P50/P95/P99)│
│  - REST API & WebSocket      │
└───────────────┬──────────────┘
                │ bulk write
                ▼
┌──────────────────────────────┐
│  Elasticsearch               │
│  - 커넥션/요청 이벤트 저장   │
│  - 의존성 링크 저장          │
│  - 시계열 메트릭 저장        │
└──────────────────────────────┘
```

---

## 1단계: C (eBPF) — 커널에서 트래픽 읽기

### eBPF가 뭔가?

eBPF는 **커널 안에서 실행되는 작은 프로그램**입니다. 커널 코드를 수정하지 않고도, 특정 이벤트(TCP 연결, 패킷 전송 등)가 발생할 때 우리 코드를 실행할 수 있습니다.

비유하면: 고속도로에 **CCTV를 설치**하는 것과 같습니다. 도로(커널)를 공사하지 않고, 카메라(eBPF)만 달아서 지나가는 차(패킷)를 관찰합니다.

### 3개의 eBPF 프로그램

Nefi는 3개의 C 파일로 3가지 트래픽을 잡습니다:

#### (1) `connection_tracker.c` — TCP 연결 추적

**어디에 붙는가:** 커널의 TCP 상태 변경 이벤트 (tracepoint)

```
App이 서버에 연결 → 커널이 TCP 상태를 바꿈 → eBPF가 감지
```

**동작 과정:**

```
① TCP 연결 시작 (ESTABLISHED)
   → 출발지/목적지 IP:Port 기록
   → 시작 시간 기록 (나노초 단위)

② 연결 중 패킷 재전송 발생
   → retransmit 카운터 +1 (네트워크 문제 지표)

③ TCP 연결 종료 (CLOSE)
   → 지속 시간 = 종료시간 - 시작시간
   → conn_event를 perf buffer로 유저스페이스에 전달
   → 맵 정리 (메모리 해제)
```

**사용하는 커널 hook:**
- `tracepoint/sock/inet_sock_set_state` — TCP 상태 변경 감지
- `tracepoint/tcp/tcp_retransmit_skb` — 패킷 재전송 감지

#### (2) `http_parser.c` — HTTP 요청/응답 파싱

**어디에 붙는가:** 커널의 TCP send/recv 함수 (kprobe)

```
App이 HTTP 요청 보냄 → tcp_sendmsg() 호출됨 → eBPF가 페이로드 첫 부분 읽음
```

**동작 과정:**

```
① App이 데이터 전송 (tcp_sendmsg)
   → 페이로드 첫 4바이트 읽기
   → "GET ", "POST", "PUT " 등인지 확인
   → HTTP면 path 파싱 (예: "/api/users")
   → 요청 시작 시간 저장

② App이 응답 수신 (tcp_recvmsg 리턴)
   → 저장해둔 요청 시작 시간 찾기
   → latency = 현재시간 - 요청시작시간
   → http_event를 perf buffer로 전달
```

**HTTP 메서드 감지 방법 (4바이트 비교):**
```c
// 메모리에서 읽은 첫 4바이트를 정수로 비교
0x20544547 = "GET "
0x54534F50 = "POST"
0x20545550 = "PUT "
```
이 방식이 문자열 비교보다 훨씬 빠릅니다. 커널 안에서는 성능이 중요하기 때문입니다.

#### (3) `dns_tracker.c` — DNS 질의 캡처

**어디에 붙는가:** 커널의 UDP 전송 함수 (kprobe)

```
App이 DNS 질의 → udp_sendmsg() 호출됨 → 목적지 포트가 53이면 → DNS 파싱
```

**동작 과정:**

```
① UDP 전송 감지 (udp_sendmsg)
   → 목적지 포트 53 확인 (DNS)
   → DNS 와이어 포맷 파싱:
     [3]www[6]google[3]com[0] → "www.google.com"
   → 쿼리 타입 추출 (A=1, AAAA=28 등)
   → dns_event를 perf buffer로 전달
```

### 커널 → 유저스페이스 데이터 전달

eBPF 프로그램은 커널 안에서 실행되므로, 결과를 유저스페이스(Go 프로그램)로 보내야 합니다. 이때 **perf buffer**를 사용합니다.

```
┌─ Kernel ──────────────────────────────┐
│                                        │
│  eBPF program → bpf_perf_event_output()│
│                    │                   │
│          ┌─────────▼─────────┐        │
│          │   Perf Buffer     │        │
│          │ (CPU별 링 버퍼)    │        │
│          └─────────┬─────────┘        │
└────────────────────│──────────────────┘
                     │ mmap으로 공유된 메모리
┌────────────────────▼──────────────────┐
│  Go (cilium/ebpf 라이브러리)          │
│  perf.Reader.Read() → 이벤트 수신     │
└───────────────────────────────────────┘
```

Perf buffer는 CPU마다 하나씩 있는 링 버퍼입니다. 커널이 쓰고, 유저스페이스가 읽습니다. 복사 없이 공유 메모리(mmap)로 전달되어 매우 빠릅니다.

### 공유 데이터 구조 (`headers/common.h`)

C(커널)와 Go(유저스페이스)가 **같은 구조체 레이아웃**을 사용해야 데이터를 올바르게 읽을 수 있습니다:

```c
struct conn_event {
    __u64 timestamp_ns;     // 8바이트
    __u32 src_ip;           // 4바이트
    __u32 dst_ip;           // 4바이트
    __u16 src_port;         // 2바이트
    __u16 dst_port;         // 2바이트
    __u64 bytes_sent;       // 8바이트
    __u64 bytes_recv;       // 8바이트
    __u64 duration_ns;      // 8바이트
    __u32 retransmits;      // 4바이트
    __u8  protocol;         // 1바이트
    __u8  _pad[3];          // 3바이트 (정렬용)
};
```

Go에서 이 바이트를 `binary.LittleEndian`으로 파싱합니다.

---

## 2단계: Go Agent — 이벤트 수집 & 전송

Agent는 **DaemonSet**으로 모든 노드에 1개씩 배포됩니다. 각 노드의 커널 트래픽을 수집합니다.

### 동작 흐름

```
main.go 시작
    │
    ├─ ① eBPF Loader 시작
    │     /opt/nefi/bpf/*.o 파일 로드
    │     perf buffer reader 생성
    │     readConnEvents() goroutine 시작
    │     readHTTPEvents() goroutine 시작
    │
    ├─ ② K8s Cache 시작
    │     Pod Informer → IP → {pod, namespace, workload, service} 매핑
    │     EndpointSlice Informer → pod → service 매핑
    │
    ├─ ③ gRPC Exporter 시작
    │     nefi-server:9090에 연결
    │
    └─ ④ Main Event Loop
          loader.Events() 채널에서 이벤트 읽기
              ↓
          K8s Cache로 IP를 Pod/Service 이름으로 변환 (enrichment)
              ↓
          exporter.Enqueue(event)
```

### 핵심: IP → K8s 메타데이터 변환

eBPF는 IP와 포트만 알려줍니다. 하지만 우리가 보고 싶은 건 **"어떤 서비스가 어떤 서비스를 호출했는가"** 입니다.

```
eBPF가 알려주는 것:
  10.244.1.5:8080 → 10.244.2.3:3306

K8s Cache가 변환한 결과:
  frontend (Deployment, default) → mysql (StatefulSet, default)
```

이 변환은 Kubernetes API의 **Informer**를 통해 이루어집니다:
- Pod IP → Pod 이름, Namespace
- Pod의 ownerReferences → Deployment/StatefulSet 이름
- EndpointSlice → Service 이름

### gRPC 전송

이벤트를 100개씩 모아서 100ms마다 서버로 전송합니다:

```
이벤트 큐 (최대 10,000개)
    ↓ 100ms마다
100개씩 배치로 묶기
    ↓
Proto 변환 (model → protobuf)
    ↓
gRPC stream.Send(EventBatch)
```

서버가 다운되면? → 큐에 최대 10,000개까지 보관하고, 지수 백오프(500ms → 30s)로 재연결합니다.

---

## 3단계: Go Server — 수신, 집계, 저장

### 이벤트 수신 (gRPC)

```
Agent → StreamEvents(stream) → Server

Server가 하는 일:
  ① proto → model 변환
  ② Elasticsearch에 저장
  ③ Aggregator에 전달 (실시간 메트릭용)
```

### 의존성 그래프 계산 (30초마다)

최근 5분간의 이벤트를 분석해서 서비스 간 관계를 찾습니다:

```
최근 커넥션/요청 이벤트 쿼리 (최대 50,000개)
    ↓
source.service → destination.service 쌍 추출
    ↓
각 쌍마다 집계:
  - callCount: 호출 횟수
  - errorCount: HTTP 5xx 응답 수
  - p99Latency: 상위 1% 지연시간
    ↓
nefi-dependencies 인덱스에 저장
```

### 메트릭 집계 (30초마다)

인메모리 히스토그램으로 실시간 메트릭을 계산합니다:

```
이벤트 도착할 때마다:
  서비스별 버킷에 latency 기록
  [1ms][5ms][10ms][25ms][50ms][100ms][250ms][500ms][1s][2.5s][5s][10s][+∞]

30초마다 flush:
  각 서비스별로:
    - P50 (중간값), P95, P99 계산
    - 호출률 (calls/interval)
    - 에러률 (errors/calls)
    - 트래픽 (bytes sent/recv)
  → nefi-metrics 인덱스에 저장
```

---

## 4단계: Elasticsearch — 저장소

4개의 날짜별 인덱스를 사용합니다:

| 인덱스 | 내용 | 예시 |
|--------|------|------|
| `nefi-connections-2026-02-09` | L4 TCP 연결 이벤트 | frontend→mysql, 150ms, 2KB |
| `nefi-requests-2026-02-09` | L7 HTTP 요청 이벤트 | GET /api/users, 200, 45ms |
| `nefi-dependencies-2026-02-09` | 서비스 의존성 링크 | frontend→api: 1,200 calls, P99 80ms |
| `nefi-metrics-2026-02-09` | 시계열 메트릭 | api: P99=120ms, error_rate=0.02 |

벌크 쓰기: 1,000개 모이거나 5초마다 flush합니다.

---

## 5단계: REST API — 프론트엔드에 데이터 제공

| 엔드포인트 | 용도 |
|-----------|------|
| `GET /api/v1/topology` | 서비스 토폴로지 그래프 (노드 + 엣지) |
| `WS /api/v1/ws/topology` | 실시간 토폴로지 업데이트 (5초마다) |
| `GET /api/v1/services` | 전체 서비스 목록 |
| `GET /api/v1/dependencies` | 서비스 간 의존성 |
| `GET /api/v1/metrics/latencies` | P50/P95/P99 지연시간 |
| `GET /api/v1/metrics/errors` | 에러율 |
| `GET /api/v1/metrics/calls` | 호출률 |
| `GET /api/v1/metrics/traffic` | 트래픽량 |
| `GET /api/v1/connections` | 원시 커넥션 이벤트 |
| `GET /api/v1/requests` | 원시 HTTP 요청 이벤트 |

---

## 전체 데이터 흐름 요약

```
Pod A가 Pod B에 HTTP 요청을 보냄
         │
         ▼
[커널] tcp_sendmsg() 호출됨
         │
         ▼
[eBPF - C] http_parser가 감지
  → "GET /api/users" 파싱
  → src=10.244.1.5, dst=10.244.2.3
  → perf buffer로 전달
         │
         ▼
[Agent - Go] perf buffer에서 이벤트 읽기
  → binary.LittleEndian으로 C struct 파싱
  → K8s Cache 조회:
    10.244.1.5 → frontend (Deployment)
    10.244.2.3 → api-server (Deployment)
  → gRPC로 서버에 전송
         │
         ▼
[Server - Go] 이벤트 수신
  → Elasticsearch에 저장 (nefi-requests-2026-02-09)
  → Aggregator에 전달 → P99 latency 계산
  → 30초마다 dependency 계산 → frontend→api-server 링크 생성
         │
         ▼
[Elasticsearch] 데이터 저장
         │
         ▼
[REST API] GET /api/v1/topology 요청 시
  → Elasticsearch에서 dependencies 쿼리
  → 서비스 노드 + 엣지 그래프 구성
  → JSON으로 프론트엔드에 반환
         │
         ▼
[UI - React] 서비스 맵 시각화
  → 노드: 서비스들
  → 엣지: 호출관계 + 메트릭 (latency, error rate, traffic)
```

---

## 파일 구조 요약

```
nefi-project/
├── bpf/                          # eBPF 프로그램 (C)
│   ├── headers/
│   │   ├── common.h              #   공유 구조체 (conn_event, http_event 등)
│   │   └── vmlinux.h             #   커널 타입 정의 (CO-RE용)
│   ├── connection_tracker.c      #   TCP 연결 추적
│   ├── http_parser.c             #   HTTP 요청/응답 파싱
│   └── dns_tracker.c             #   DNS 질의 캡처
│
├── cmd/
│   ├── nefi-agent/main.go        # Agent 진입점
│   └── nefi-server/main.go       # Server 진입점
│
├── internal/
│   ├── agent/
│   │   ├── ebpf/loader.go        #   eBPF 로드 & perf buffer 읽기
│   │   ├── k8s/cache.go          #   IP → K8s 메타데이터 캐시
│   │   └── exporter/grpc.go      #   gRPC 배치 전송
│   ├── server/
│   │   ├── ingestion/grpc.go     #   gRPC 수신 & proto 변환
│   │   ├── storage/elasticsearch/ #   ES 읽기/쓰기
│   │   ├── graph/dependency.go   #   서비스 의존성 계산
│   │   ├── metrics/aggregator.go #   실시간 메트릭 집계
│   │   └── api/handler.go        #   REST API 핸들러
│   ├── model/                    # 공유 데이터 모델
│   └── proto/                    # gRPC protobuf 정의
│
├── ui/                           # React 프론트엔드
└── deploy/helm/nefi/             # Kubernetes Helm 차트
```
