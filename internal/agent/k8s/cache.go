package k8s

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/gihongjo/nefi/internal/model"
)

// Cache maintains an in-memory mapping from IP addresses to Kubernetes resource
// metadata (Pod, Namespace, owning Workload, Service). It uses client-go shared
// informers to watch Pod, Service, and EndpointSlice resources and keeps the
// cache up to date as cluster state changes.
type Cache struct {
	logger    *zap.Logger
	clientset kubernetes.Interface
	factory   informers.SharedInformerFactory

	mu        sync.RWMutex
	endpoints map[string]*model.Endpoint // IP -> Endpoint

	// podToServices tracks which services expose a given pod key (namespace/name).
	podToServices map[string]string // "namespace/podName" -> serviceName
}

// NewCache creates a Cache backed by a Kubernetes clientset. If kubeconfig is
// empty, in-cluster configuration is used (the normal case when running as a
// DaemonSet). Otherwise the given kubeconfig path is used (useful for local
// development).
func NewCache(logger *zap.Logger, kubeconfig string) (*Cache, error) {
	var cfg *rest.Config
	var err error

	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubeconfig from %s: %w", kubeconfig, err)
		}
	} else {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	return &Cache{
		logger:        logger,
		clientset:     clientset,
		endpoints:     make(map[string]*model.Endpoint),
		podToServices: make(map[string]string),
	}, nil
}

// Start begins watching Kubernetes resources. It blocks until the initial cache
// sync is complete, then continues watching until ctx is cancelled.
func (c *Cache) Start(ctx context.Context) error {
	c.factory = informers.NewSharedInformerFactory(c.clientset, 30*time.Second)

	// Register event handlers for Pods.
	podInformer := c.factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.onPodAdd(obj) },
		UpdateFunc: func(_, obj interface{}) { c.onPodAdd(obj) },
		DeleteFunc: func(obj interface{}) { c.onPodDelete(obj) },
	})

	// Register event handlers for EndpointSlices (maps service -> pod IPs).
	epSliceInformer := c.factory.Discovery().V1().EndpointSlices().Informer()
	epSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.onEndpointSliceUpdate(obj) },
		UpdateFunc: func(_, obj interface{}) { c.onEndpointSliceUpdate(obj) },
		DeleteFunc: func(obj interface{}) { c.onEndpointSliceDelete(obj) },
	})

	// Start all informers.
	c.factory.Start(ctx.Done())

	// Wait for initial cache sync.
	c.logger.Info("waiting for informer cache sync")
	synced := c.factory.WaitForCacheSync(ctx.Done())
	for informerType, ok := range synced {
		if !ok {
			return fmt.Errorf("informer %v failed to sync", informerType)
		}
	}
	c.logger.Info("informer cache sync complete")

	// Block until context cancellation.
	<-ctx.Done()
	return nil
}

// Lookup returns the Endpoint metadata for the given IP address, or nil if the
// IP is not known to the cache.
func (c *Cache) Lookup(ip string) *model.Endpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ep, ok := c.endpoints[ip]
	if !ok {
		return nil
	}
	// Return a copy so callers cannot mutate cache state.
	copy := *ep
	return &copy
}

// onPodAdd handles Pod add/update events. It indexes the pod by its IP and
// resolves the owning workload via ownerReferences.
func (c *Cache) onPodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}

	podIP := pod.Status.PodIP
	if podIP == "" {
		return
	}

	workload, workloadType := c.resolveWorkload(pod)
	svcName := c.lookupServiceForPod(pod.Namespace, pod.Name)

	ep := &model.Endpoint{
		IP:           podIP,
		Pod:          pod.Name,
		Namespace:    pod.Namespace,
		Workload:     workload,
		WorkloadType: workloadType,
		Service:      svcName,
	}

	c.mu.Lock()
	c.endpoints[podIP] = ep
	c.mu.Unlock()
}

// onPodDelete removes the pod's IP from the cache.
func (c *Cache) onPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// Handle deleted final state unknown.
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}

	podIP := pod.Status.PodIP
	if podIP == "" {
		return
	}

	c.mu.Lock()
	delete(c.endpoints, podIP)
	c.mu.Unlock()
}

// onEndpointSliceUpdate processes an EndpointSlice to map pod IPs to the parent
// Service name, then refreshes cached Endpoints that belong to those pods.
func (c *Cache) onEndpointSliceUpdate(obj interface{}) {
	eps, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return
	}

	svcName := eps.Labels[discoveryv1.LabelServiceName]
	if svcName == "" {
		return
	}

	c.mu.Lock()
	for _, ep := range eps.Endpoints {
		if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
			podKey := eps.Namespace + "/" + ep.TargetRef.Name
			c.podToServices[podKey] = svcName
		}
		// Update any existing cached endpoints with the service name.
		for _, addr := range ep.Addresses {
			if existing, ok := c.endpoints[addr]; ok {
				existing.Service = svcName
			}
		}
	}
	c.mu.Unlock()
}

// onEndpointSliceDelete removes the pod-to-service mapping for the deleted slice.
func (c *Cache) onEndpointSliceDelete(obj interface{}) {
	eps, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		eps, ok = tombstone.Obj.(*discoveryv1.EndpointSlice)
		if !ok {
			return
		}
	}

	c.mu.Lock()
	for _, ep := range eps.Endpoints {
		if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
			podKey := eps.Namespace + "/" + ep.TargetRef.Name
			delete(c.podToServices, podKey)
		}
		for _, addr := range ep.Addresses {
			if existing, ok := c.endpoints[addr]; ok {
				existing.Service = ""
			}
		}
	}
	c.mu.Unlock()
}

// resolveWorkload walks the ownerReference chain from a Pod to determine the
// top-level workload controller (Deployment, StatefulSet, DaemonSet, Job, etc.)
// and its kind. For the common case of Pod -> ReplicaSet -> Deployment, it
// resolves through both levels.
func (c *Cache) resolveWorkload(pod *corev1.Pod) (name string, kind string) {
	if len(pod.OwnerReferences) == 0 {
		return pod.Name, "Pod"
	}

	owner := pod.OwnerReferences[0]

	switch owner.Kind {
	case "ReplicaSet":
		// Try to resolve ReplicaSet -> Deployment.
		deployName := c.resolveReplicaSetOwner(pod.Namespace, owner.Name)
		if deployName != "" {
			return deployName, "Deployment"
		}
		// Standalone ReplicaSet; strip the hash suffix for readability.
		return stripReplicaSetHash(owner.Name), "ReplicaSet"

	case "StatefulSet":
		return owner.Name, "StatefulSet"

	case "DaemonSet":
		return owner.Name, "DaemonSet"

	case "Job":
		return owner.Name, "Job"

	default:
		return owner.Name, owner.Kind
	}
}

// resolveReplicaSetOwner fetches the ReplicaSet and returns its owning
// Deployment name, if any. Returns "" if the RS has no Deployment owner.
func (c *Cache) resolveReplicaSetOwner(namespace, rsName string) string {
	rs, err := c.clientset.AppsV1().ReplicaSets(namespace).Get(
		context.Background(), rsName, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	for _, ref := range rs.OwnerReferences {
		if ref.Kind == "Deployment" {
			return ref.Name
		}
	}
	return ""
}

// lookupServiceForPod returns the cached service name for the given pod, or ""
// if no service is known.
func (c *Cache) lookupServiceForPod(namespace, podName string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.podToServices[namespace+"/"+podName]
}

// stripReplicaSetHash removes the trailing hash suffix from a ReplicaSet name
// (e.g., "my-deploy-6b8f7c9d4" -> "my-deploy").
func stripReplicaSetHash(name string) string {
	idx := strings.LastIndex(name, "-")
	if idx <= 0 {
		return name
	}
	// Verify the suffix looks like a hash (alphanumeric, typically 8-10 chars).
	suffix := name[idx+1:]
	if len(suffix) >= 5 && len(suffix) <= 16 {
		return name[:idx]
	}
	return name
}

// Ensure appsv1 is used (it is imported for the ReplicaSet Get call).
var _ = appsv1.SchemeGroupVersion
