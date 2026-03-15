// Package k8s resolves host PIDs to Kubernetes namespace/pod names.
//
// 동작 원리:
//   /proc/<pid>/cgroup 에서 pod UID를 파싱하고,
//   k8s API로 해당 pod의 namespace와 이름을 조회한다.
//
//   API 호출 비용을 줄이기 위해 두 단계 캐시를 사용한다:
//     1. podsByUID: 30초마다 갱신되는 노드 내 pod 목록 (UID → PodInfo)
//     2. pidCache:  PID → PodInfo (pod가 재시작되면 무효화됨)
package k8s

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// PodInfo holds the Kubernetes identity of a container process.
type PodInfo struct {
	Namespace string
	PodName   string
}

// Resolver maps host PIDs and pod IPs to Kubernetes pod metadata.
type Resolver struct {
	client    kubernetes.Interface
	nodeName  string
	podsByUID map[string]*PodInfo // pod UID → PodInfo  (this node only)
	podsByIP  map[string]*PodInfo // pod IP  → PodInfo  (cluster-wide)
	pidCache  map[uint32]*PodInfo // pid     → PodInfo  (nil = not a pod)
	mu        sync.RWMutex
}

// NewResolver creates a resolver using the in-cluster kubeconfig.
// It performs an initial pod list fetch and starts a background refresh loop.
func NewResolver() (*Resolver, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}

	r := &Resolver{
		client:    client,
		nodeName:  os.Getenv("NODE_NAME"),
		podsByUID: make(map[string]*PodInfo),
		podsByIP:  make(map[string]*PodInfo),
		pidCache:  make(map[uint32]*PodInfo),
	}

	if err := r.refreshPods(); err != nil {
		return nil, fmt.Errorf("initial pod list: %w", err)
	}

	go r.runRefresh(30 * time.Second)

	return r, nil
}

// Resolve returns the PodInfo for the given host PID, or nil if the
// process is not running inside a Kubernetes pod.
func (r *Resolver) Resolve(pid uint32) *PodInfo {
	r.mu.RLock()
	if info, ok := r.pidCache[pid]; ok {
		r.mu.RUnlock()
		return info
	}
	r.mu.RUnlock()

	uid, _ := podUIDFromCgroup(pid)
	var info *PodInfo
	if uid != "" {
		r.mu.RLock()
		info = r.podsByUID[uid]
		r.mu.RUnlock()
	}

	r.mu.Lock()
	r.pidCache[pid] = info
	r.mu.Unlock()

	return info
}

// refreshPods fetches pods and rebuilds lookup maps:
//   - podsByUID: this node's pods only (UID → PodInfo), used for PID resolution
//   - podsByIP:  all cluster pods (IP → PodInfo), used for remote IP resolution
//
// pidCache is cleared so stale entries are re-resolved on next access.
func (r *Resolver) refreshPods() error {
	// Fetch this node's pods for UID-based PID resolution.
	nodeOpts := metav1.ListOptions{}
	if r.nodeName != "" {
		nodeOpts.FieldSelector = "spec.nodeName=" + r.nodeName
	}
	nodePods, err := r.client.CoreV1().Pods("").List(context.Background(), nodeOpts)
	if err != nil {
		return err
	}

	// Fetch all cluster pods for IP-based remote pod resolution.
	allPods, err := r.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	newByUID := make(map[string]*PodInfo, len(nodePods.Items))
	for i := range nodePods.Items {
		pod := &nodePods.Items[i]
		newByUID[string(pod.UID)] = &PodInfo{
			Namespace: pod.Namespace,
			PodName:   pod.Name,
		}
	}

	newByIP := make(map[string]*PodInfo, len(allPods.Items))
	for i := range allPods.Items {
		pod := &allPods.Items[i]
		if pod.Status.PodIP == "" {
			continue
		}
		newByIP[pod.Status.PodIP] = &PodInfo{
			Namespace: pod.Namespace,
			PodName:   pod.Name,
		}
	}

	r.mu.Lock()
	r.podsByUID = newByUID
	r.podsByIP = newByIP
	r.pidCache = make(map[uint32]*PodInfo)
	r.mu.Unlock()

	return nil
}

// ResolveIP returns the PodInfo for the given remote IP (host byte order),
// or nil if no pod with that IP is known.
// ip is in host byte order as returned by bpf_ntohl in the BPF program.
func (r *Resolver) ResolveIP(ip uint32) *PodInfo {
	if ip == 0 {
		return nil
	}
	ipStr := fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.podsByIP[ipStr]
}

func (r *Resolver) runRefresh(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		r.refreshPods() //nolint:errcheck
	}
}

// podUIDFromCgroup reads /proc/<pid>/cgroup and extracts the Kubernetes
// pod UID from the cgroup path.
//
// Supported formats:
//   cgroup v1: /kubepods/burstable/pod<uid>/<container-id>
//   cgroup v2: /kubepods.slice/.../kubepods-burstable-pod<uid-underscored>.slice/...
func podUIDFromCgroup(pid uint32) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// format: <hierarchy-id>:<controllers>:<cgroup-path>
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if uid := extractPodUID(parts[2]); uid != "" {
			return uid, nil
		}
	}
	return "", scanner.Err()
}

// extractPodUID parses a pod UID from a cgroup path string.
func extractPodUID(cgroupPath string) string {
	// cgroup v1: .../pod<uid>/...
	if idx := strings.Index(cgroupPath, "/pod"); idx >= 0 {
		rest := cgroupPath[idx+4:]
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		uid := rest[:end]
		if isValidUID(uid) {
			return uid
		}
	}

	// cgroup v2 systemd: ...-pod<uid-underscored>.slice/...
	// systemd escapes dashes in unit names as underscores
	if idx := strings.Index(cgroupPath, "-pod"); idx >= 0 {
		rest := cgroupPath[idx+4:]
		end := strings.IndexByte(rest, '.')
		if end < 0 {
			end = len(rest)
		}
		uid := strings.ReplaceAll(rest[:end], "_", "-")
		if isValidUID(uid) {
			return uid
		}
	}

	return ""
}

// isValidUID checks whether s looks like a Kubernetes UID (UUID format).
func isValidUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}
