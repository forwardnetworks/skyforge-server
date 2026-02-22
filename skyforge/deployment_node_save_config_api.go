package skyforge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
	"k8s.io/client-go/kubernetes"
)

type UserScopeDeploymentNodeSaveConfigResponse struct {
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
	Container string `json:"container,omitempty"`
	Command   string `json:"command,omitempty"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
	Message   string `json:"message,omitempty"`
}

// SaveUserScopeDeploymentNodeConfig triggers a best-effort "save config" operation on a node.
//
// For EOS/cEOS, this runs `write memory`.
//
//encore:api auth method=POST path=/api/users/:id/deployments/:deploymentID/nodes/:node/save-config
func (s *Service) SaveUserScopeDeploymentNodeConfig(ctx context.Context, id, deploymentID, node string) (*UserScopeDeploymentNodeSaveConfigResponse, error) {
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

	dep, err := s.getWorkspaceDeployment(ctx, pc.userScope.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("save config is only available for clabernetes-backed deployments").Err()
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	k8sNamespace, _ := cfgAny["k8sNamespace"].(string)
	topologyName, _ := cfgAny["topologyName"].(string)
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	topologyName = strings.TrimSpace(topologyName)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesUserScopeNamespace(pc.userScope.Slug)
	}
	if topologyName == "" {
		labName, _ := cfgAny["labName"].(string)
		topologyName = clabernetesTopologyName(strings.TrimSpace(labName))
	}
	if topologyName == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("missing topology name").Err()
	}

	// Derive node kind from the most recent topology artifact, if present.
	nodeKind := ""
	taskType := ""
	switch typ {
	case "netlab-c9s":
		taskType = "netlab-c9s-run"
	case "clabernetes":
		taskType = "clabernetes-run"
	}
	if taskType != "" {
		graph, err := s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, taskType)
		if err == nil && graph != nil {
			for _, n := range graph.Nodes {
				if strings.TrimSpace(n.ID) == node {
					nodeKind = strings.TrimSpace(n.Kind)
					break
				}
			}
		}
	}

	// Currently only EOS/cEOS has an explicit "save config" we can run safely.
	lk := strings.ToLower(nodeKind)
	if !strings.Contains(lk, "eos") && !strings.Contains(lk, "ceos") {
		return &UserScopeDeploymentNodeSaveConfigResponse{
			Skipped: true,
			Message: fmt.Sprintf("save-config not implemented for node kind %q", nodeKind),
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

	_, err = kubernetes.NewForConfig(kcfg)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube client unavailable").Err()
	}

	ctxExec, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	container := "nos"
	container = strings.TrimSpace(container)
	script := `set -eu
command -v Cli >/dev/null 2>&1 || exit 0
i=0
while [ $i -lt 60 ]; do
  Cli -p 15 -c "show version" >/dev/null 2>&1 && break
  sleep 1
  i=$((i+1))
done
Cli -p 15 -c "write memory" >/dev/null 2>&1 || true
echo "ok: write memory"`

	stdout, stderr, execErr := execPodShell(ctxExec, kcfg, k8sNamespace, podName, container, script)
	if execErr != nil && strings.Contains(strings.ToLower(execErr.Error()), "container") {
		stdout2, stderr2, err2 := execPodShell(ctxExec, kcfg, k8sNamespace, podName, "", script)
		if err2 == nil {
			stdout, stderr, execErr = stdout2, stderr2, nil
			container = ""
		} else {
			execErr = err2
		}
	}

	resp := &UserScopeDeploymentNodeSaveConfigResponse{
		Namespace: k8sNamespace,
		PodName:   podName,
		Container: container,
		Command:   "Cli -p 15 -c 'write memory'",
		Stdout:    strings.TrimSpace(stdout),
		Stderr:    strings.TrimSpace(stderr),
	}
	if execErr != nil {
		rlog.Warn("save-config failed", "userScope", pc.userScope.ID, "deployment", dep.ID, "node", node, "err", execErr)
		if s.db != nil {
			_ = insertDeploymentUIEvent(ctx, s.db, pc.userScope.ID, dep.ID, pc.claims.Username, "node.save-config.failed", map[string]any{
				"node":      node,
				"nodeKind":  nodeKind,
				"podName":   podName,
				"container": container,
				"stderr":    resp.Stderr,
			})
			_ = notifyDeploymentEventPG(ctx, s.db, pc.userScope.ID, dep.ID)
		}
		return resp, errs.B().Code(errs.Unavailable).Msg("save-config failed").Err()
	}

	if s.db != nil {
		_ = insertDeploymentUIEvent(ctx, s.db, pc.userScope.ID, dep.ID, pc.claims.Username, "node.save-config", map[string]any{
			"node":      node,
			"nodeKind":  nodeKind,
			"podName":   podName,
			"container": container,
		})
		_ = notifyDeploymentEventPG(ctx, s.db, pc.userScope.ID, dep.ID)
	}

	return resp, nil
}
