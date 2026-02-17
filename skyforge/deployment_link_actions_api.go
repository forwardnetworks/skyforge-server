package skyforge

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"

	"encore.app/storage"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DeploymentLinkAdminRequest struct {
	EdgeID string `json:"edgeId"`
	Action string `json:"action"` // up|down
}

type DeploymentLinkAdminResult struct {
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

type DeploymentLinkAdminResponse struct {
	AppliedAt string                      `json:"appliedAt"`
	Action    string                      `json:"action"`
	EdgeID    string                      `json:"edgeId"`
	Results   []DeploymentLinkAdminResult `json:"results"`
}

// UpdateUserDeploymentLinkAdmin performs administrative link operations (up/down) on a topology edge.
func (s *Service) UpdateUserDeploymentLinkAdmin(ctx context.Context, id, deploymentID string, req *DeploymentLinkAdminRequest) (*DeploymentLinkAdminResponse, error) {
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
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	edgeID := strings.TrimSpace(req.EdgeID)
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if edgeID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("edgeId is required").Err()
	}
	if action != "up" && action != "down" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("action must be up or down").Err()
	}

	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("link operations are only available for clabernetes-backed deployments").Err()
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
	edge := findTopologyEdge(graph, edgeID)
	if edge == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("edge not found").Err()
	}
	if strings.TrimSpace(edge.SourceIf) == "" || strings.TrimSpace(edge.TargetIf) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("edge missing interface mapping").Err()
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube config unavailable").Err()
	}
	clientset, err := newKubeClientset(kcfg)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube client unavailable").Err()
	}

	type endpoint struct {
		Node string
		If   string
	}
	endpoints := []endpoint{
		{Node: strings.TrimSpace(edge.Source), If: strings.TrimSpace(edge.SourceIf)},
		{Node: strings.TrimSpace(edge.Target), If: strings.TrimSpace(edge.TargetIf)},
	}

	var results []DeploymentLinkAdminResult
	for _, ep := range endpoints {
		if ep.Node == "" || ep.If == "" {
			continue
		}
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		podName, err := resolveClabernetesNodePod(runCtx, k8sNamespace, topologyName, ep.Node)
		cancel()
		if err != nil {
			results = append(results, DeploymentLinkAdminResult{
				Node:      ep.Node,
				Namespace: k8sNamespace,
				Pod:       "",
				Container: "",
				IfName:    ep.If,
				Command:   "",
				Error:     "pod not found",
			})
			continue
		}

		runCtx, cancel = context.WithTimeout(ctx, 25*time.Second)
		container, err := selectNetemContainer(runCtx, clientset, k8sNamespace, podName)
		cancel()
		if err != nil {
			container = ""
		}

		script := buildLinkAdminScript(ep.If, action)
		runCtx, cancel = context.WithTimeout(ctx, 25*time.Second)
		stdout, stderr, err := execPodShell(runCtx, kcfg, k8sNamespace, podName, container, script)
		cancel()
		out := DeploymentLinkAdminResult{
			Node:      ep.Node,
			Namespace: k8sNamespace,
			Pod:       podName,
			Container: container,
			IfName:    ep.If,
			Command:   fmt.Sprintf("ip link set dev %s %s", ep.If, action),
			Stdout:    strings.TrimSpace(stdout),
			Stderr:    strings.TrimSpace(stderr),
		}
		if err != nil {
			out.Error = err.Error()
		}
		results = append(results, out)
	}

	appliedAt := time.Now().UTC().Format(time.RFC3339)
	if s.db != nil {
		payload := map[string]any{
			"edgeId":  edgeID,
			"action":  action,
			"results": results,
		}
		if err := insertDeploymentUIEvent(ctx, s.db, pc.context.ID, deploymentID, pc.claims.Username, "link."+action, payload); err == nil {
			_ = notifyDeploymentEventPG(ctx, s.db, pc.context.ID, deploymentID)
		}
	}
	return &DeploymentLinkAdminResponse{
		AppliedAt: appliedAt,
		Action:    action,
		EdgeID:    edgeID,
		Results:   results,
	}, nil
}

type DeploymentLinkCaptureRequest struct {
	EdgeID          string `json:"edgeId"`
	Side            string `json:"side"` // source|target
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	MaxPackets      int    `json:"maxPackets,omitempty"`
	Snaplen         int    `json:"snaplen,omitempty"`
	MaxBytes        int    `json:"maxBytes,omitempty"`
}

type DeploymentLinkCaptureResponse struct {
	CapturedAt  string `json:"capturedAt"`
	EdgeID      string `json:"edgeId"`
	Side        string `json:"side"`
	Node        string `json:"node"`
	IfName      string `json:"ifName"`
	ArtifactKey string `json:"artifactKey"`
	SizeBytes   int    `json:"sizeBytes"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
}

// CaptureUserDeploymentLinkPcap captures a short pcap on a topology link and uploads it as a owner artifact.
func (s *Service) CaptureUserDeploymentLinkPcap(ctx context.Context, id, deploymentID string, req *DeploymentLinkCaptureRequest) (*DeploymentLinkCaptureResponse, error) {
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
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	edgeID := strings.TrimSpace(req.EdgeID)
	if edgeID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("edgeId is required").Err()
	}
	side := strings.ToLower(strings.TrimSpace(req.Side))
	if side == "" {
		side = "source"
	}
	if side != "source" && side != "target" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("side must be source or target").Err()
	}
	dur := req.DurationSeconds
	if dur <= 0 {
		dur = 10
	}
	if dur > 30 {
		dur = 30
	}
	pkts := req.MaxPackets
	if pkts <= 0 {
		pkts = 2500
	}
	if pkts > 20000 {
		pkts = 20000
	}
	snaplen := req.Snaplen
	if snaplen <= 0 {
		snaplen = 192
	}
	if snaplen > 2048 {
		snaplen = 2048
	}
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if maxBytes > 25<<20 {
		maxBytes = 25 << 20
	}

	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("pcap capture is only available for clabernetes-backed deployments").Err()
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
	edge := findTopologyEdge(graph, edgeID)
	if edge == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("edge not found").Err()
	}

	node := strings.TrimSpace(edge.Source)
	ifName := strings.TrimSpace(edge.SourceIf)
	if side == "target" {
		node = strings.TrimSpace(edge.Target)
		ifName = strings.TrimSpace(edge.TargetIf)
	}
	if node == "" || ifName == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("edge missing interface mapping").Err()
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube config unavailable").Err()
	}
	clientset, err := newKubeClientset(kcfg)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube client unavailable").Err()
	}

	ctxResolve, cancel := context.WithTimeout(ctx, 5*time.Second)
	podName, err := resolveClabernetesNodePod(ctxResolve, k8sNamespace, topologyName, node)
	cancel()
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("node pod not found").Err()
	}

	container := ""
	{
		ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		if c, err := selectNetemContainer(ctx2, clientset, k8sNamespace, podName); err == nil {
			container = c
		}
	}
	if container == "" {
		container = "launcher"
	}

	key := fmt.Sprintf("captures/%s/%s-%s-%s.pcap", strings.TrimSpace(deploymentID), sanitizeArtifactPart(edgeID), side, time.Now().UTC().Format("20060102T150405Z"))
	script := buildTcpdumpCaptureScript(ifName, dur, pkts, snaplen, maxBytes)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(dur+20)*time.Second)
	stdout, stderr, err := execPodShell(runCtx, kcfg, k8sNamespace, podName, container, script)
	cancel()
	if err != nil {
		// If tcpdump isn't present in the selected container, try other non-NOS containers.
		if strings.Contains(stderr, "tcpdump not found") || strings.Contains(stderr, "timeout not found") {
			ctxGet, cancelGet := context.WithTimeout(ctx, 5*time.Second)
			pod, getErr := clientset.CoreV1().Pods(k8sNamespace).Get(ctxGet, podName, metav1.GetOptions{})
			cancelGet()
			if getErr == nil && pod != nil {
				for _, c := range pod.Spec.Containers {
					name := strings.TrimSpace(c.Name)
					if name == "" || name == "nos" || name == container {
						continue
					}
					runCtx2, cancel2 := context.WithTimeout(ctx, time.Duration(dur+20)*time.Second)
					stdout2, stderr2, err2 := execPodShell(runCtx2, kcfg, k8sNamespace, podName, name, script)
					cancel2()
					if err2 == nil {
						stdout, stderr, err = stdout2, stderr2, nil
						container = name
						break
					}
				}
			}
		}
	}
	if err != nil {
		rlog.Warn("pcap capture failed", "node", node, "pod", podName, "err", err, "stderr", strings.TrimSpace(stderr))
		if strings.Contains(stderr, "tcpdump not found") || strings.Contains(stderr, "timeout not found") {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("pcap capture requires tcpdump+timeout in the launcher container image").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("pcap capture failed").Err()
	}

	b64, size, parseErr := parseCaptureOutput(stdout)
	if parseErr != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("pcap capture parse failed").Err()
	}
	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("pcap decode failed").Err()
	}
	if size <= 0 {
		size = len(payload)
	}

	storageSvc, err := storage.GetService()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("artifact storage unavailable").Err()
	}
	if err := storageSvc.Write(ctx, &storage.WriteRequest{ObjectName: artifactObjectName(pc.context.ID, key), Data: payload}); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to upload pcap").Err()
	}

	resp := &DeploymentLinkCaptureResponse{
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
		EdgeID:      edgeID,
		Side:        side,
		Node:        node,
		IfName:      ifName,
		ArtifactKey: key,
		SizeBytes:   size,
		Stdout:      "",
		Stderr:      strings.TrimSpace(stderr),
	}

	if s.db != nil {
		payloadEv := map[string]any{
			"edgeId":      edgeID,
			"side":        side,
			"node":        node,
			"ifName":      ifName,
			"artifactKey": key,
			"sizeBytes":   size,
		}
		if err := insertDeploymentUIEvent(ctx, s.db, pc.context.ID, deploymentID, pc.claims.Username, "link.capture", payloadEv); err == nil {
			_ = notifyDeploymentEventPG(ctx, s.db, pc.context.ID, deploymentID)
		}
	}

	return resp, nil
}

func sanitizeArtifactPart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ":", "-")
	if s == "" {
		return "edge"
	}
	return s
}

func buildLinkAdminScript(ifName, action string) string {
	ifName = strings.TrimSpace(ifName)
	action = strings.ToLower(strings.TrimSpace(action))
	return strings.Join([]string{
		"set -eu",
		"IF=" + shellEscape(ifName),
		"ip link set dev \"$IF\" " + action,
		"ip -br link show dev \"$IF\" || true",
	}, "\n") + "\n"
}

func buildTcpdumpCaptureScript(ifName string, dur, packets, snaplen, maxBytes int) string {
	ifName = strings.TrimSpace(ifName)
	return strings.Join([]string{
		"set -eu",
		"IF=" + shellEscape(ifName),
		fmt.Sprintf("DUR=%d", dur),
		fmt.Sprintf("PKTS=%d", packets),
		fmt.Sprintf("SNAPLEN=%d", snaplen),
		fmt.Sprintf("MAX=%d", maxBytes),
		"FILE=\"/tmp/skyforge-capture-$$.pcap\"",
		"if ! command -v tcpdump >/dev/null 2>&1; then echo \"tcpdump not found\" >&2; exit 2; fi",
		"if ! command -v timeout >/dev/null 2>&1; then echo \"timeout not found\" >&2; exit 2; fi",
		"timeout -k 2s \"${DUR}s\" tcpdump -nn -U -i \"$IF\" -s \"$SNAPLEN\" -c \"$PKTS\" -w \"$FILE\" >/dev/null 2>&1 || true",
		"SZ=$(stat -c%s \"$FILE\" 2>/dev/null || wc -c <\"$FILE\" | tr -d ' ')",
		"if [ \"$SZ\" -gt \"$MAX\" ]; then echo \"pcap too large: $SZ bytes\" >&2; exit 3; fi",
		"echo \"__SKYFORGE_SIZE__:$SZ\"",
		"echo \"__SKYFORGE_BEGIN__\"",
		"base64 -w0 \"$FILE\"",
		"echo",
		"echo \"__SKYFORGE_END__\"",
	}, "\n") + "\n"
}

func parseCaptureOutput(stdout string) (b64 string, size int, err error) {
	stdout = strings.ReplaceAll(stdout, "\r\n", "\n")
	lines := strings.Split(stdout, "\n")
	in := false
	var buf strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "__SKYFORGE_SIZE__:") {
			raw := strings.TrimPrefix(line, "__SKYFORGE_SIZE__:")
			if n, e := strconv.Atoi(strings.TrimSpace(raw)); e == nil && n > 0 {
				size = n
			}
			continue
		}
		if line == "__SKYFORGE_BEGIN__" {
			in = true
			continue
		}
		if line == "__SKYFORGE_END__" {
			in = false
			continue
		}
		if !in || line == "" {
			continue
		}
		buf.WriteString(line)
	}
	b64 = strings.TrimSpace(buf.String())
	if b64 == "" {
		return "", size, fmt.Errorf("missing capture payload")
	}
	return b64, size, nil
}

func findTopologyEdge(graph *DeploymentTopologyResponse, edgeID string) *TopologyEdge {
	if graph == nil {
		return nil
	}
	edgeID = strings.TrimSpace(edgeID)
	for i := range graph.Edges {
		if strings.TrimSpace(graph.Edges[i].ID) == edgeID {
			return &graph.Edges[i]
		}
	}
	return nil
}
