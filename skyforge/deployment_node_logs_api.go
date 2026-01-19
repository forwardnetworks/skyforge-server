package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type WorkspaceDeploymentNodeLogsParams struct {
	Tail      int    `query:"tail" encore:"optional"`
	Container string `query:"container" encore:"optional"`
}

type WorkspaceDeploymentNodeLogsResponse struct {
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	Container string `json:"container,omitempty"`
	Tail      int    `json:"tail,omitempty"`
	Logs      string `json:"logs,omitempty"`
}

// GetWorkspaceDeploymentNodeLogs returns recent log lines for a clabernetes node pod.
//
// This powers the "View logs" action in the topology UI (similar to the c9s VSCode extension).
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/nodes/:node/logs
func (s *Service) GetWorkspaceDeploymentNodeLogs(
	ctx context.Context,
	id, deploymentID, node string,
	params *WorkspaceDeploymentNodeLogsParams,
) (*WorkspaceDeploymentNodeLogsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
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

	tail := 200
	if params != nil && params.Tail > 0 {
		switch {
		case params.Tail > 2000:
			tail = 2000
		default:
			tail = params.Tail
		}
	}
	container := ""
	if params != nil {
		container = strings.TrimSpace(params.Container)
	}

	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("node logs are only available for clabernetes-backed deployments").Err()
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

	if container == "" {
		kcfg, err := kubeInClusterConfig()
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("kube config unavailable").Err()
		}
		clientset, err := kubernetes.NewForConfig(kcfg)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("kube client unavailable").Err()
		}
		ctxGet, cancel := context.WithTimeout(ctx, 3*time.Second)
		pod, err := clientset.CoreV1().Pods(k8sNamespace).Get(ctxGet, podName, metav1.GetOptions{})
		cancel()
		if err == nil && pod != nil {
			best := ""
			for _, c := range pod.Spec.Containers {
				name := strings.TrimSpace(c.Name)
				if name == "" {
					continue
				}
				if best == "" {
					best = name
				}
				if name == "nos" {
					best = name
					break
				}
				if name == "node" {
					best = name
				}
			}
			container = best
		}
	}

	client, err := kubeHTTPClient()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube http client unavailable").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	logs, err := kubeGetPodLogsTail(ctxReq, client, k8sNamespace, podName, container, tail)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load node logs").Err()
	}

	return &WorkspaceDeploymentNodeLogsResponse{
		Namespace: k8sNamespace,
		PodName:   podName,
		Container: container,
		Tail:      tail,
		Logs:      logs,
	}, nil
}
