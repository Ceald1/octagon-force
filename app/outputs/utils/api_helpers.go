package utils

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type EventData interface {
	SigmaEvent | NetworkEvent | FileSystemEvent
}

type Output[T EventData] struct {
	Source    string
	Data      T
	EventName string
}

type ContainerPIDProvider interface {
	GetContainerPID() string
}

// Support both pod_UUID and podUUID / hyphenated cgroup formats
// var podUIDRegex = regexp.MustCompile(`pod[_-]?([a-f0-9]{8}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{12})`)
var podUIDRegex = regexp.MustCompile(`pod[_-]?([a-f0-9]{8}[-_]?[a-f0-9]{4}[-_]?[a-f0-9]{4}[-_]?[a-f0-9]{4}[-_]?[a-f0-9]{12})`)

// PodResolver manages the informer cache and UID lookup
type PodResolver struct {
	informer cache.SharedIndexInformer
	client   kubernetes.Interface
}

var (
	globalResolver *PodResolver
	resolverOnce   sync.Once
)

// InitResolver initializes the client-go informer factory once
func InitResolver(ctx context.Context, client kubernetes.Interface) (*PodResolver, error) {
	var err error
	resolverOnce.Do(func() {
		if client == nil {
			var config *rest.Config
			config, err = rest.InClusterConfig()
			if err != nil {
				kubeconfig := os.Getenv("KUBECONFIG")
				config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
				if err != nil {
					return
				}
			}
			client, err = kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
		}

		factory := informers.NewSharedInformerFactory(client, 10*time.Minute)
		podInformer := factory.Core().V1().Pods().Informer()

		// Register custom UID indexer for O(1) lookups
		err = podInformer.AddIndexers(cache.Indexers{
			"byUID": func(obj interface{}) ([]string, error) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					return nil, nil
				}
				return []string{string(pod.UID)}, nil
			},
		})
		if err != nil {
			return
		}

		factory.Start(ctx.Done())
		if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
			err = fmt.Errorf("failed to sync pod informer cache")
			return
		}

		globalResolver = &PodResolver{
			informer: podInformer,
			client:   client,
		}
	})

	return globalResolver, err
}

func ResolveIP(ip string) (podName string, podNs string, err error) {

	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return "", "", err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", "", err
	}

	svcList, err := clientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return "", "", err
	}

	for _, svc := range svcList.Items {
		if svc.Spec.ClusterIP == ip {
			return svc.Name, svc.Namespace, nil
		}
	}
	podList, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return "", "", err
	}
	for _, pod := range podList.Items {
		if pod.Status.PodIP == ip {
			return pod.Name, pod.Namespace, nil
		}
	}

	return "", "", fmt.Errorf("no pod or service found matching %s", ip)

}

func (o Output[T]) GetPod() (podName string, podNS string, err error) {
	var PID string
	var ParentPID string

	switch v := any(o.Data).(type) {
	case NetworkEvent:
		PID = v.PID
		ParentPID = v.ParentPID
	case *NetworkEvent:
		if v != nil {
			PID = v.PID
			ParentPID = v.ParentPID
		}
	case SigmaEvent:
		PID = v.PID
		ParentPID = v.ParentPID
	case *SigmaEvent:
		if v != nil {
			PID = v.PID
			ParentPID = v.ParentPID
		}
	case FileSystemEvent:
		PID = v.PID
	case *FileSystemEvent:
		if v != nil {
			PID = v.PID
		}
	case ContainerPIDProvider:
		PID = v.GetContainerPID()
	default:
		return "", "", fmt.Errorf("unsupported event data type %T for pod lookup", o.Data)
	}

	if PID == "" || PID == "0" {
		return "", "", fmt.Errorf("invalid or missing container PID in event")
	}

	// Attempt lookup using primary PID first
	podName, podNS, err = GetPodFromPID(PID)
	if err == nil && podName != "" {
		return podName, podNS, nil
	}
	if err != nil {
		log.Warn(err.Error())
	}

	// Fallback to ParentPID if primary PID lookup fails (e.g. short-lived exited process)
	if ParentPID != "" && ParentPID != "0" {
		podName, podNS, err = GetPodFromPID(ParentPID)
		if err == nil && podName != "" {
			return podName, podNS, nil
		}
	}
	if err != nil {
		log.Warn(err.Error())
	}

	return "", "", fmt.Errorf("unable to resolve pod for PID %s or parent %s", PID, ParentPID)
}

//func (o Output[T]) GetPod() (podName string, podNS string, err error) {
//	var PID string
//	var ParentPID string
//
//	switch v := any(o.Data).(type) {
//	case NetworkEvent:
//		PID = v.PID
//		ParentPID = v.ParentPID
//	case *NetworkEvent:
//		if v != nil {
//			PID = v.PID
//		}
//	case SigmaEvent:
//		PID = v.PID
//	case *SigmaEvent:
//		if v != nil {
//			PID = v.PID
//		}
//	case FileSystemEvent:
//		PID = v.PID
//	case *FileSystemEvent:
//		if v != nil {
//			PID = v.PID
//		}
//	case ContainerPIDProvider:
//		PID = v.GetContainerPID()
//	default:
//		return "", "", fmt.Errorf("unsupported event data type %T for pod lookup", o.Data)
//	}
//
//	if PID == "" || PID == "0" || ParentPID == "0" {
//		return "", "", fmt.Errorf("invalid or missing container PID in event")
//	}
//	podName, podNS, err = GetPodFromPID(ParentPID)
//
//	if len(podName) < 1 || err != nil {
//		if err != nil {
//			log.Warn(err.Error())
//		}
//		podName, podNS, err = GetPodFromPID(PID)
//		if err != nil {
//			log.Warn(err)
//		}
//	}
//	return podName, podNS, err
//
//	//return pod.Name, pod.Namespace, nil
//}

func GetPodFromPID(PID string) (string, string, error) {
	uid, err := GetPodUIDFromCgroupID(PID)
	if err != nil {
		return "", "", err
	}
	if uid == "" {
		return "", "", nil // does not exist, skip!!!
	}

	// Fallback to direct API list search if informer isn't initialized (e.g. in standalone unit tests)
	if globalResolver == nil {
		return resolvePodDirectAPI(uid)
	}

	// O(1) lookup via Informer cache index
	objs, err := globalResolver.informer.GetIndexer().ByIndex("byUID", uid)
	if err != nil {
		return "", "", err
	}
	if len(objs) == 0 {
		return "", "", fmt.Errorf("no pod found matching UID %s", uid)
	}

	pod := objs[0].(*corev1.Pod)
	return pod.Name, pod.Namespace, err
}

// Fallback direct list search (safe against "field label not supported" errors)
func resolvePodDirectAPI(uid string) (podName string, podNS string, err error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return "", "", err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", "", err
	}

	podList, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return "", "", err
	}

	for _, pod := range podList.Items {
		if string(pod.UID) == uid {
			return pod.Name, pod.Namespace, nil
		}
	}

	return "", "", fmt.Errorf("no pod found matching UID %s", uid)
}

func GetPodUIDFromCgroupID(containerPID string) (string, error) {
	// Respect PROC_ROOT env var if mounted in a pod (e.g., /host/proc)
	procRoot := os.Getenv("PROC_ROOT")
	if procRoot == "" {
		procRoot = "/proc"
	}

	if containerPID == "" {
		return "", nil // does not exist, skip!!
	}
	cGroupPath := filepath.Join(procRoot, containerPID, "cgroup")

	file, err := os.Open(cGroupPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("failed to open cgroup for PID %s at %s: %w", containerPID, cGroupPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		if matches := podUIDRegex.FindStringSubmatch(parts[2]); len(matches) > 1 {
			// Convert systemd's escaped underscores back to standard UUID hyphens
			podUID := strings.ReplaceAll(matches[1], "_", "-")
			return podUID, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading cgroup for PID %s: %w", containerPID, err)
	}

	return "", nil //fmt.Errorf("process %s is not running inside a Kubernetes Pod", containerPID)
} // does not exist, return nothing!
