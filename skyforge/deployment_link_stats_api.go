package skyforge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type LinkStatsSnapshot struct {
	GeneratedAt string          `json:"generatedAt"`
	Source      string          `json:"source"`
	Edges       []LinkEdgeStats `json:"edges"`
}

type LinkEdgeStats struct {
	EdgeID string `json:"edgeId"`

	SourceNode string `json:"sourceNode"`
	SourceIf   string `json:"sourceIf"`
	SourceRX   uint64 `json:"sourceRxBytes"`
	SourceTX   uint64 `json:"sourceTxBytes"`
	SourceRxPk uint64 `json:"sourceRxPackets"`
	SourceTxPk uint64 `json:"sourceTxPackets"`
	SourceRxDr uint64 `json:"sourceRxDropped"`
	SourceTxDr uint64 `json:"sourceTxDropped"`

	TargetNode string `json:"targetNode"`
	TargetIf   string `json:"targetIf"`
	TargetRX   uint64 `json:"targetRxBytes"`
	TargetTX   uint64 `json:"targetTxBytes"`
	TargetRxPk uint64 `json:"targetRxPackets"`
	TargetTxPk uint64 `json:"targetTxPackets"`
	TargetRxDr uint64 `json:"targetRxDropped"`
	TargetTxDr uint64 `json:"targetTxDropped"`
}

// GetUserScopeDeploymentLinkStats returns a snapshot of interface counters for each topology edge.
//
// This is used to render live link utilization on the topology graph (similar to c9s VSCode extension).
//
//encore:api auth method=GET path=/api/users/:id/deployments/:deploymentID/links/stats
func (s *Service) GetUserScopeDeploymentLinkStats(ctx context.Context, id, deploymentID string) (*LinkStatsSnapshot, error) {
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

	dep, err := s.getUserScopeDeployment(ctx, pc.userScope.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("link stats are only available for clabernetes-backed deployments").Err()
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

	taskType := ""
	switch typ {
	case "netlab-c9s":
		taskType = "netlab-c9s-run"
	case "clabernetes":
		taskType = "clabernetes-run"
	}
	graph, err := s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, taskType)
	if err != nil {
		return nil, err
	}

	// Collect per-node required interfaces.
	want := map[string]map[string]struct{}{} // node -> if -> {}
	for _, e := range graph.Edges {
		if strings.TrimSpace(e.Source) == "" || strings.TrimSpace(e.Target) == "" {
			continue
		}
		sif := strings.TrimSpace(e.SourceIf)
		tif := strings.TrimSpace(e.TargetIf)
		if sif != "" {
			if want[e.Source] == nil {
				want[e.Source] = map[string]struct{}{}
			}
			want[e.Source][sif] = struct{}{}
		}
		if tif != "" {
			if want[e.Target] == nil {
				want[e.Target] = map[string]struct{}{}
			}
			want[e.Target][tif] = struct{}{}
		}
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("kube config unavailable").Err()
	}

	type ifCounters struct {
		RxBytes   uint64
		TxBytes   uint64
		RxPackets uint64
		TxPackets uint64
		RxDropped uint64
		TxDropped uint64
	}
	perNode := map[string]map[string]ifCounters{}

	// One exec per node.
	for nodeName, ifs := range want {
		ctxResolve, cancel := context.WithTimeout(ctx, 5*time.Second)
		podName, err := resolveClabernetesNodePod(ctxResolve, k8sNamespace, topologyName, nodeName)
		cancel()
		if err != nil {
			continue
		}
		container := ""
		{
			ctx2, cancel2 := context.WithTimeout(ctx, 3*time.Second)
			defer cancel2()
			// Reuse logic from link impairment to pick launcher-like container.
			// It falls back to a non-NOS container if present.
			// If it fails, we'll still try without specifying container.
			clientset, err := newKubeClientset(kcfg)
			if err == nil {
				if c, err := selectNetemContainer(ctx2, clientset, k8sNamespace, podName); err == nil {
					container = c
				}
			}
		}

		// Build script that prints JSON lines: {"if":"eth1","rx_bytes":...}
		var ifList []string
		for ifName := range ifs {
			ifList = append(ifList, ifName)
		}
		if len(ifList) == 0 {
			continue
		}
		script := buildIfCountersScript(ifList)
		ctxExec, cancel := context.WithTimeout(ctx, 10*time.Second)
		stdout, stderr, err := execPodShell(ctxExec, kcfg, k8sNamespace, podName, container, script)
		cancel()
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "container") {
			ctxExec2, cancel2 := context.WithTimeout(ctx, 10*time.Second)
			stdout2, stderr2, err2 := execPodShell(ctxExec2, kcfg, k8sNamespace, podName, "", script)
			cancel2()
			if err2 == nil {
				stdout, stderr, err = stdout2, stderr2, nil
			} else {
				err = err2
			}
		}
		if err != nil {
			rlog.Debug("link stats exec failed", "node", nodeName, "pod", podName, "err", err, "stderr", strings.TrimSpace(stderr))
			continue
		}

		m := map[string]ifCounters{}
		sc := bufio.NewScanner(strings.NewReader(stdout))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var row struct {
				If       string `json:"if"`
				RxBytes  uint64 `json:"rx_bytes"`
				TxBytes  uint64 `json:"tx_bytes"`
				RxPk     uint64 `json:"rx_packets"`
				TxPk     uint64 `json:"tx_packets"`
				RxDrop   uint64 `json:"rx_dropped"`
				TxDrop   uint64 `json:"tx_dropped"`
				NotFound bool   `json:"not_found"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				continue
			}
			if strings.TrimSpace(row.If) == "" || row.NotFound {
				continue
			}
			m[row.If] = ifCounters{
				RxBytes:   row.RxBytes,
				TxBytes:   row.TxBytes,
				RxPackets: row.RxPk,
				TxPackets: row.TxPk,
				RxDropped: row.RxDrop,
				TxDropped: row.TxDrop,
			}
		}
		perNode[nodeName] = m
	}

	var edges []LinkEdgeStats
	for _, e := range graph.Edges {
		sif := strings.TrimSpace(e.SourceIf)
		tif := strings.TrimSpace(e.TargetIf)
		if sif == "" || tif == "" {
			continue
		}
		src := perNode[e.Source][sif]
		dst := perNode[e.Target][tif]
		edges = append(edges, LinkEdgeStats{
			EdgeID:     strings.TrimSpace(e.ID),
			SourceNode: e.Source,
			SourceIf:   sif,
			SourceRX:   src.RxBytes,
			SourceTX:   src.TxBytes,
			SourceRxPk: src.RxPackets,
			SourceTxPk: src.TxPackets,
			SourceRxDr: src.RxDropped,
			SourceTxDr: src.TxDropped,
			TargetNode: e.Target,
			TargetIf:   tif,
			TargetRX:   dst.RxBytes,
			TargetTX:   dst.TxBytes,
			TargetRxPk: dst.RxPackets,
			TargetTxPk: dst.TxPackets,
			TargetRxDr: dst.RxDropped,
			TargetTxDr: dst.TxDropped,
		})
	}

	return &LinkStatsSnapshot{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      "launcher",
		Edges:       edges,
	}, nil
}

type LinkStatsSSEEvent struct {
	Type     string             `json:"type"`
	Snapshot *LinkStatsSnapshot `json:"snapshot,omitempty"`
	Error    string             `json:"error,omitempty"`
}

// GetUserScopeDeploymentLinkStatsEvents streams link stats snapshots as SSE.
//
//encore:api auth raw method=GET path=/api/users/:id/deployments/:deploymentID/links/stats/events
func (s *Service) GetUserScopeDeploymentLinkStatsEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userScopeKey := strings.TrimSpace(req.PathValue("id"))
	deploymentID := strings.TrimSpace(req.PathValue("deploymentID"))
	if userScopeKey == "" || deploymentID == "" {
		// Best-effort path param extraction (PathValue is only populated when the
		// underlying mux supports it).
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		// expected: api/users/<id>/deployments/<deploymentID>/links/stats/events
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "users":
				if userScopeKey == "" {
					userScopeKey = strings.TrimSpace(parts[i+1])
				}
			case "deployments":
				if deploymentID == "" {
					deploymentID = strings.TrimSpace(parts[i+1])
				}
			}
		}
	}
	if userScopeKey == "" || deploymentID == "" {
		http.Error(w, "invalid path params", http.StatusBadRequest)
		return
	}
	_, _, ws, err := s.loadUserScopeByKey(userScopeKey)
	if err != nil || strings.TrimSpace(ws.ID) == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if userScopeAccessLevelForClaims(s.cfg, ws, claims) == "none" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	stream, err := newSSEStream(w)
	if err != nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	stream.comment("ok")
	stream.flush()

	ctx := req.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastID := int64(0)
	send := func(ev LinkStatsSSEEvent) {
		lastID++
		stream.eventJSON(lastID, "stats", ev)
		stream.flush()
	}

	// initial
	snap, err := s.GetUserScopeDeploymentLinkStats(ctx, userScopeKey, deploymentID)
	if err != nil {
		send(LinkStatsSSEEvent{Type: "error", Error: err.Error()})
	} else {
		send(LinkStatsSSEEvent{Type: "snapshot", Snapshot: snap})
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := s.GetUserScopeDeploymentLinkStats(ctx, userScopeKey, deploymentID)
			if err != nil {
				send(LinkStatsSSEEvent{Type: "error", Error: err.Error()})
				continue
			}
			send(LinkStatsSSEEvent{Type: "snapshot", Snapshot: snap})
		}
	}
}

func newKubeClientset(cfg *rest.Config) (*kubernetes.Clientset, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kube config required")
	}
	return kubernetes.NewForConfig(cfg)
}

func buildIfCountersScript(ifs []string) string {
	var buf bytes.Buffer
	buf.WriteString("set -eu\n")
	buf.WriteString("get() { [ -f \"$1\" ] && cat \"$1\" || echo 0; }\n")
	for _, ifName := range ifs {
		ifName = strings.TrimSpace(ifName)
		if ifName == "" {
			continue
		}
		esc := shellEscape(ifName)
		buf.WriteString("IF=" + esc + "\n")
		buf.WriteString("BASE=\"/sys/class/net/$IF/statistics\"\n")
		buf.WriteString("if [ ! -d \"/sys/class/net/$IF\" ]; then echo '{\"if\":'\"'\"'$IF'\"'\"',\"not_found\":true}'; continue; fi\n")
		buf.WriteString("RXB=$(get \"$BASE/rx_bytes\"); TXB=$(get \"$BASE/tx_bytes\"); ")
		buf.WriteString("RXP=$(get \"$BASE/rx_packets\"); TXP=$(get \"$BASE/tx_packets\"); ")
		buf.WriteString("RXD=$(get \"$BASE/rx_dropped\"); TXD=$(get \"$BASE/tx_dropped\");\n")
		buf.WriteString("printf '{\"if\":\"%s\",\"rx_bytes\":%s,\"tx_bytes\":%s,\"rx_packets\":%s,\"tx_packets\":%s,\"rx_dropped\":%s,\"tx_dropped\":%s}\\n' \"$IF\" \"$RXB\" \"$TXB\" \"$RXP\" \"$TXP\" \"$RXD\" \"$TXD\"\n")
	}
	return buf.String()
}
