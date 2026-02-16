package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type DeploymentNodeRunningConfigResponse struct {
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	Container string `json:"container,omitempty"`
	Node      string `json:"node,omitempty"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
	Message   string `json:"message,omitempty"`
}

// GetUserDeploymentNodeRunningConfig fetches the running config from a NOS node (best-effort).
//
// Currently supports EOS/cEOS via `Cli -c "show running-config"`.
func (s *Service) GetUserDeploymentNodeRunningConfig(ctx context.Context, id, deploymentID, node string) (*DeploymentNodeRunningConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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

	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("running config is only available for clabernetes-backed deployments").Err()
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	k8sNamespace, _ := cfgAny["k8sNamespace"].(string)
	topologyName, _ := cfgAny["topologyName"].(string)
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	topologyName = strings.TrimSpace(topologyName)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesOwnerNamespace(pc.context.Slug)
	}
	if topologyName == "" {
		labName, _ := cfgAny["labName"].(string)
		topologyName = clabernetesTopologyName(strings.TrimSpace(labName))
	}
	if topologyName == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("missing topology name").Err()
	}

	taskType := "clabernetes-run"
	if typ == "netlab-c9s" {
		taskType = "netlab-c9s-run"
	}
	graph, err := s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, taskType)
	if err != nil {
		return nil, err
	}
	kind := ""
	for _, n := range graph.Nodes {
		if strings.TrimSpace(n.ID) == node {
			kind = strings.ToLower(strings.TrimSpace(n.Kind))
			break
		}
	}
	if !(strings.Contains(kind, "eos") || strings.Contains(kind, "ceos")) {
		return &DeploymentNodeRunningConfigResponse{
			Node:    node,
			Skipped: true,
			Message: "running config is only supported for EOS/cEOS nodes",
		}, nil
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

	container := "nos"
	{
		ctxGet, cancel := context.WithTimeout(ctx, 3*time.Second)
		pod, err := clientset.CoreV1().Pods(k8sNamespace).Get(ctxGet, podName, metav1.GetOptions{})
		cancel()
		if err == nil && pod != nil {
			foundNos := false
			for _, c := range pod.Spec.Containers {
				name := strings.TrimSpace(c.Name)
				if name == "nos" {
					foundNos = true
					break
				}
			}
			if !foundNos && len(pod.Spec.Containers) > 0 {
				container = strings.TrimSpace(pod.Spec.Containers[0].Name)
			}
		}
	}

	script := strings.Join([]string{
		"set -eu",
		"if command -v Cli >/dev/null 2>&1; then Cli -c 'show running-config'; exit 0; fi",
		"if command -v vtysh >/dev/null 2>&1; then vtysh -c 'show running-config'; exit 0; fi",
		"echo 'no supported CLI found' >&2; exit 2",
	}, "\n") + "\n"

	ctxExec, cancel := context.WithTimeout(ctx, 20*time.Second)
	stdout, stderr, err := execPodShell(ctxExec, kcfg, k8sNamespace, podName, container, script)
	cancel()
	if err != nil {
		if s.db != nil {
			_ = insertDeploymentUIEvent(ctx, s.db, pc.context.ID, dep.ID, pc.claims.Username, "node.running-config.failed", map[string]any{
				"node":      node,
				"podName":   podName,
				"container": container,
			})
			_ = notifyDeploymentEventPG(ctx, s.db, pc.context.ID, dep.ID)
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to fetch running config").Err()
	}
	resp := &DeploymentNodeRunningConfigResponse{
		Namespace: k8sNamespace,
		PodName:   podName,
		Container: container,
		Node:      node,
		Stdout:    strings.TrimSpace(stdout),
		Stderr:    strings.TrimSpace(stderr),
	}
	if s.db != nil {
		_ = insertDeploymentUIEvent(ctx, s.db, pc.context.ID, dep.ID, pc.claims.Username, "node.running-config", map[string]any{
			"node":      node,
			"podName":   podName,
			"container": container,
		})
		_ = notifyDeploymentEventPG(ctx, s.db, pc.context.ID, dep.ID)
	}
	return resp, nil
}
