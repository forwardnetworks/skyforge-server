package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type WorkspaceDeploymentNodeDescribeResponse struct {
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	NodeName  string `json:"nodeName,omitempty"`

	Phase   string `json:"phase,omitempty"`
	PodIP   string `json:"podIP,omitempty"`
	HostIP  string `json:"hostIP,omitempty"`
	QoS     string `json:"qosClass,omitempty"`
	Message string `json:"message,omitempty"`

	Containers []WorkspacePodContainer `json:"containers,omitempty"`
}

type WorkspacePodContainer struct {
	Name         string `json:"name,omitempty"`
	Image        string `json:"image,omitempty"`
	Ready        bool   `json:"ready,omitempty"`
	RestartCount int32  `json:"restartCount,omitempty"`
	State        string `json:"state,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Message      string `json:"message,omitempty"`
}

// GetWorkspaceDeploymentNodeDescribe returns a lightweight summary of the clabernetes node pod.
//
//encore:api auth method=GET path=/api/users/:id/deployments/:deploymentID/nodes/:node/describe
func (s *Service) GetWorkspaceDeploymentNodeDescribe(ctx context.Context, id, deploymentID, node string) (*WorkspaceDeploymentNodeDescribeResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	node = strings.TrimSpace(node)
	if node == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("node is required").Err()
	}

	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("node inspection is only available for clabernetes-backed deployments").Err()
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	k8sNamespace, _ := cfgAny["k8sNamespace"].(string)
	topologyName, _ := cfgAny["topologyName"].(string)
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	topologyName = strings.TrimSpace(topologyName)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
	}
	if topologyName == "" {
		labName, _ := cfgAny["labName"].(string)
		topologyName = clabernetesTopologyName(strings.TrimSpace(labName))
	}
	if topologyName == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("missing topology name").Err()
	}

	ctxResolve, cancel := context.WithTimeout(ctx, 5*time.Second)
	podName, err := resolveClabernetesNodePod(ctxResolve, k8sNamespace, topologyName, node)
	cancel()
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("node pod not found").Err()
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube config unavailable").Err()
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube client unavailable").Err()
	}

	ctxGet, cancel := context.WithTimeout(ctx, 5*time.Second)
	pod, err := clientset.CoreV1().Pods(k8sNamespace).Get(ctxGet, podName, metav1.GetOptions{})
	cancel()
	if err != nil || pod == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load pod").Err()
	}

	resp := &WorkspaceDeploymentNodeDescribeResponse{
		Namespace: k8sNamespace,
		PodName:   podName,
		NodeName:  strings.TrimSpace(pod.Spec.NodeName),
		Phase:     string(pod.Status.Phase),
		PodIP:     strings.TrimSpace(pod.Status.PodIP),
		HostIP:    strings.TrimSpace(pod.Status.HostIP),
		QoS:       string(pod.Status.QOSClass),
		Message:   strings.TrimSpace(pod.Status.Message),
	}

	index := map[string]corev1.ContainerStatus{}
	for _, st := range pod.Status.ContainerStatuses {
		if strings.TrimSpace(st.Name) == "" {
			continue
		}
		index[st.Name] = st
	}

	for _, c := range pod.Spec.Containers {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			continue
		}
		out := WorkspacePodContainer{
			Name:  name,
			Image: strings.TrimSpace(c.Image),
		}
		if st, ok := index[name]; ok {
			out.Ready = st.Ready
			out.RestartCount = st.RestartCount
			switch {
			case st.State.Running != nil:
				out.State = "running"
				if !st.State.Running.StartedAt.IsZero() {
					out.Message = "startedAt=" + st.State.Running.StartedAt.Time.UTC().Format(time.RFC3339)
				}
			case st.State.Waiting != nil:
				out.State = "waiting"
				out.Reason = strings.TrimSpace(st.State.Waiting.Reason)
				out.Message = strings.TrimSpace(st.State.Waiting.Message)
			case st.State.Terminated != nil:
				out.State = "terminated"
				out.Reason = strings.TrimSpace(st.State.Terminated.Reason)
				out.Message = strings.TrimSpace(st.State.Terminated.Message)
			default:
				out.State = "unknown"
			}
		}
		resp.Containers = append(resp.Containers, out)
	}
	return resp, nil
}
