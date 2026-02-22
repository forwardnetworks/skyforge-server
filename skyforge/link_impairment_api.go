package skyforge

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type LinkImpairmentRequest struct {
	EdgeID     string  `json:"edgeId"`
	Action     string  `json:"action"` // set|clear
	DelayMs    int     `json:"delayMs,omitempty"`
	JitterMs   int     `json:"jitterMs,omitempty"`
	LossPct    float64 `json:"lossPct,omitempty"`
	DupPct     float64 `json:"dupPct,omitempty"`
	CorruptPct float64 `json:"corruptPct,omitempty"`
	ReorderPct float64 `json:"reorderPct,omitempty"`
	RateKbps   int     `json:"rateKbps,omitempty"`
}

type LinkImpairmentResponse struct {
	AppliedAt string                 `json:"appliedAt"`
	Edge      TopologyEdge           `json:"edge"`
	Results   []LinkImpairmentResult `json:"results"`
}

type LinkImpairmentResult struct {
	Node      string `json:"node"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	IfName    string `json:"ifName"`
	Command   string `json:"command"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SetWorkspaceDeploymentLinkImpairment applies or clears traffic impairment settings for a single link.
//
// The impairment is applied "outside" of the network OS by executing `tc` in the clabernetes launcher
// container (or another non-NOS container in the same pod netns).
//
//encore:api auth method=POST path=/api/users/:id/deployments/:deploymentID/links/impair
func (s *Service) SetWorkspaceDeploymentLinkImpairment(ctx context.Context, id, deploymentID string, req *LinkImpairmentRequest) (*LinkImpairmentResponse, error) {
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
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request is required").Err()
	}
	edgeID := strings.TrimSpace(req.EdgeID)
	if edgeID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("edgeId is required").Err()
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "set"
	}
	if action != "set" && action != "clear" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("action must be 'set' or 'clear'").Err()
	}
	if req.DelayMs < 0 || req.JitterMs < 0 || req.LossPct < 0 || req.DupPct < 0 || req.CorruptPct < 0 || req.ReorderPct < 0 || req.RateKbps < 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("impairment values must be non-negative").Err()
	}
	if req.LossPct > 100 || req.DupPct > 100 || req.CorruptPct > 100 || req.ReorderPct > 100 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("impairment pct fields must be <= 100").Err()
	}

	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	taskType := ""
	switch typ {
	case "netlab-c9s":
		taskType = "netlab-c9s-run"
	case "clabernetes":
		taskType = "clabernetes-run"
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("link impairment is only available for clabernetes-backed deployments").Err()
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

	graph, err := s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, taskType)
	if err != nil {
		return nil, err
	}
	var edge *TopologyEdge
	for i := range graph.Edges {
		if strings.TrimSpace(graph.Edges[i].ID) == edgeID {
			edge = &graph.Edges[i]
			break
		}
	}
	if edge == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("link not found in topology").Err()
	}
	if strings.TrimSpace(edge.SourceIf) == "" || strings.TrimSpace(edge.TargetIf) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("link endpoints are missing interface names").Err()
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube config unavailable").Err()
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube client unavailable").Err()
	}

	runCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	results := []LinkImpairmentResult{}
	apply := func(node, ifName string) LinkImpairmentResult {
		res := LinkImpairmentResult{
			Node:      node,
			Namespace: k8sNamespace,
			IfName:    ifName,
		}
		podName, err := resolveClabernetesNodePod(runCtx, k8sNamespace, topologyName, node)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		res.Pod = podName
		container, err := selectNetemContainer(runCtx, clientset, k8sNamespace, podName)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		res.Container = container

		script := tcScript(action, ifName, req)
		res.Command = script
		stdout, stderr, err := execPodShell(runCtx, kcfg, k8sNamespace, podName, container, script)
		res.Stdout = strings.TrimSpace(stdout)
		res.Stderr = strings.TrimSpace(stderr)
		if err != nil {
			res.Error = err.Error()
		}
		return res
	}

	results = append(results, apply(edge.Source, edge.SourceIf))
	results = append(results, apply(edge.Target, edge.TargetIf))

	rlog.Info("link impairment applied", "workspace", pc.workspace.ID, "deployment", dep.ID, "edge", edgeID, "action", action)

	if s.db != nil {
		ev := map[string]any{
			"edgeId":     edgeID,
			"action":     action,
			"delayMs":    req.DelayMs,
			"jitterMs":   req.JitterMs,
			"lossPct":    req.LossPct,
			"dupPct":     req.DupPct,
			"corruptPct": req.CorruptPct,
			"reorderPct": req.ReorderPct,
			"rateKbps":   req.RateKbps,
			"results":    results,
		}
		if err := insertDeploymentUIEvent(ctx, s.db, pc.workspace.ID, dep.ID, pc.claims.Username, "link.impair."+action, ev); err == nil {
			_ = notifyDeploymentEventPG(ctx, s.db, pc.workspace.ID, dep.ID)
		}
	}

	return &LinkImpairmentResponse{
		AppliedAt: time.Now().UTC().Format(time.RFC3339),
		Edge:      *edge,
		Results:   results,
	}, nil
}

func tcScript(action, ifName string, req *LinkImpairmentRequest) string {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return ""
	}
	if action == "clear" {
		return fmt.Sprintf("tc qdisc del dev %s root 2>/dev/null || true", shellEscape(ifName))
	}

	netemParts := []string{}
	if req.DelayMs > 0 {
		if req.JitterMs > 0 {
			netemParts = append(netemParts, fmt.Sprintf("delay %dms %dms", req.DelayMs, req.JitterMs))
		} else {
			netemParts = append(netemParts, fmt.Sprintf("delay %dms", req.DelayMs))
		}
	}
	if req.LossPct > 0 {
		netemParts = append(netemParts, fmt.Sprintf("loss %.3f%%", req.LossPct))
	}
	if req.DupPct > 0 {
		netemParts = append(netemParts, fmt.Sprintf("duplicate %.3f%%", req.DupPct))
	}
	if req.CorruptPct > 0 {
		netemParts = append(netemParts, fmt.Sprintf("corrupt %.3f%%", req.CorruptPct))
	}
	if req.ReorderPct > 0 {
		netemParts = append(netemParts, fmt.Sprintf("reorder %.3f%%", req.ReorderPct))
	}
	netemArgs := strings.Join(netemParts, " ")
	netemSuffix := ""
	if strings.TrimSpace(netemArgs) != "" {
		netemSuffix = " " + netemArgs
	}

	// Always install a root netem qdisc so we can optionally attach TBF.
	lines := []string{
		fmt.Sprintf("tc qdisc replace dev %s root handle 1: netem%s", shellEscape(ifName), netemSuffix),
	}
	if req.RateKbps > 0 {
		lines = append(lines, fmt.Sprintf("tc qdisc replace dev %s parent 1: handle 10: tbf rate %dkbit burst 32kbit latency 400ms", shellEscape(ifName), req.RateKbps))
	}
	return strings.Join(lines, " && ")
}

func shellEscape(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\\'\"$;&|<>`(){}[]*?!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func selectNetemContainer(ctx context.Context, clientset *kubernetes.Clientset, ns, podName string) (string, error) {
	ctxGet, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	pod, err := clientset.CoreV1().Pods(ns).Get(ctxGet, podName, metav1.GetOptions{})
	if err != nil || pod == nil {
		return "", fmt.Errorf("failed to load pod for exec")
	}
	best := ""
	for _, c := range pod.Spec.Containers {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			continue
		}
		l := strings.ToLower(name)
		if strings.Contains(l, "launcher") {
			return name, nil
		}
		if best == "" && l != "nos" {
			best = name
		}
	}
	if best != "" {
		return best, nil
	}
	if len(pod.Spec.Containers) > 0 {
		return strings.TrimSpace(pod.Spec.Containers[0].Name), nil
	}
	return "", fmt.Errorf("pod has no containers")
}

func execPodShell(ctx context.Context, kcfg *rest.Config, ns, podName, container, script string) (stdout, stderr string, err error) {
	script = strings.TrimSpace(script)
	if script == "" {
		return "", "", fmt.Errorf("empty command")
	}
	cmd := []string{"sh", "-lc", script}
	return execPodCommand(ctx, kcfg, ns, podName, container, cmd)
}

func execPodCommand(ctx context.Context, kcfg *rest.Config, ns, podName, container string, cmd []string) (stdout, stderr string, err error) {
	if kcfg == nil {
		return "", "", fmt.Errorf("kube config required")
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return "", "", err
	}

	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(ns).
		SubResource("exec")
	req.VersionedParams(opts, scheme.ParameterCodec)
	execURL := req.URL()

	executor, err := remotecommand.NewSPDYExecutor(kcfg, http.MethodPost, execURL)
	if err != nil {
		return "", "", err
	}

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	streamErr := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &outBuf,
		Stderr: &errBuf,
	})
	return outBuf.String(), errBuf.String(), streamErr
}
