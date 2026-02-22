package skyforge

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"k8s.io/client-go/kubernetes"
)

type DeploymentNodeInterfacesResponse struct {
	Namespace   string                    `json:"namespace,omitempty"`
	PodName     string                    `json:"podName,omitempty"`
	Node        string                    `json:"node,omitempty"`
	GeneratedAt string                    `json:"generatedAt"`
	Interfaces  []DeploymentNodeInterface `json:"interfaces"`
}

type DeploymentNodeInterface struct {
	IfName    string `json:"ifName"`
	OperState string `json:"operState,omitempty"`
	RxBytes   uint64 `json:"rxBytes,omitempty"`
	TxBytes   uint64 `json:"txBytes,omitempty"`
	RxPackets uint64 `json:"rxPackets,omitempty"`
	TxPackets uint64 `json:"txPackets,omitempty"`
	RxDropped uint64 `json:"rxDropped,omitempty"`
	TxDropped uint64 `json:"txDropped,omitempty"`
	PeerNode  string `json:"peerNode,omitempty"`
	PeerIf    string `json:"peerIf,omitempty"`
	EdgeID    string `json:"edgeId,omitempty"`
}

// GetWorkspaceDeploymentNodeInterfaces returns interface stats (launcher container) for a clabernetes node.
//
//encore:api auth method=GET path=/api/users/:id/deployments/:deploymentID/nodes/:node/interfaces
func (s *Service) GetWorkspaceDeploymentNodeInterfaces(ctx context.Context, id, deploymentID, node string) (*DeploymentNodeInterfacesResponse, error) {
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
		return nil, errs.B().Code(errs.InvalidArgument).Msg("interface stats are only available for clabernetes-backed deployments").Err()
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

	taskType := "clabernetes-run"
	if typ == "netlab-c9s" {
		taskType = "netlab-c9s-run"
	}
	graph, err := s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, taskType)
	if err != nil {
		return nil, err
	}

	peer := map[string]DeploymentNodeInterface{} // if -> peer/edge
	needIf := map[string]struct{}{}
	for _, e := range graph.Edges {
		if strings.TrimSpace(e.Source) == "" || strings.TrimSpace(e.Target) == "" {
			continue
		}
		if strings.TrimSpace(e.SourceIf) == "" || strings.TrimSpace(e.TargetIf) == "" {
			continue
		}
		if strings.TrimSpace(e.Source) == node {
			needIf[e.SourceIf] = struct{}{}
			peer[e.SourceIf] = DeploymentNodeInterface{
				IfName:   e.SourceIf,
				PeerNode: e.Target,
				PeerIf:   e.TargetIf,
				EdgeID:   e.ID,
			}
		}
		if strings.TrimSpace(e.Target) == node {
			needIf[e.TargetIf] = struct{}{}
			peer[e.TargetIf] = DeploymentNodeInterface{
				IfName:   e.TargetIf,
				PeerNode: e.Source,
				PeerIf:   e.SourceIf,
				EdgeID:   e.ID,
			}
		}
	}
	needIf["eth0"] = struct{}{}

	var ifList []string
	for name := range needIf {
		ifList = append(ifList, strings.TrimSpace(name))
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

	container := ""
	{
		ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		if c, err := selectNetemContainer(ctx2, clientset, k8sNamespace, podName); err == nil {
			container = c
		}
	}

	script := buildInterfacesScript(ifList)
	ctxExec, cancel := context.WithTimeout(ctx, 10*time.Second)
	stdout, _, err := execPodShell(ctxExec, kcfg, k8sNamespace, podName, container, script)
	cancel()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to read interface stats").Err()
	}

	var ifStats []DeploymentNodeInterface
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			If        string `json:"if"`
			Oper      string `json:"oper"`
			RxBytes   uint64 `json:"rx_bytes"`
			TxBytes   uint64 `json:"tx_bytes"`
			RxPackets uint64 `json:"rx_packets"`
			TxPackets uint64 `json:"tx_packets"`
			RxDropped uint64 `json:"rx_dropped"`
			TxDropped uint64 `json:"tx_dropped"`
			NotFound  bool   `json:"not_found"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if strings.TrimSpace(row.If) == "" || row.NotFound {
			continue
		}
		base := peer[row.If]
		base.IfName = row.If
		base.OperState = strings.TrimSpace(row.Oper)
		base.RxBytes = row.RxBytes
		base.TxBytes = row.TxBytes
		base.RxPackets = row.RxPackets
		base.TxPackets = row.TxPackets
		base.RxDropped = row.RxDropped
		base.TxDropped = row.TxDropped
		ifStats = append(ifStats, base)
	}

	return &DeploymentNodeInterfacesResponse{
		Namespace:   k8sNamespace,
		PodName:     podName,
		Node:        node,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Interfaces:  ifStats,
	}, nil
}

func buildInterfacesScript(ifs []string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("get() { [ -f \"$1\" ] && cat \"$1\" || echo 0; }\n")
	for _, ifName := range ifs {
		ifName = strings.TrimSpace(ifName)
		if ifName == "" {
			continue
		}
		esc := shellEscape(ifName)
		b.WriteString("IF=" + esc + "\n")
		b.WriteString("BASE=\"/sys/class/net/$IF/statistics\"\n")
		b.WriteString("if [ ! -d \"/sys/class/net/$IF\" ]; then echo '{\"if\":'\"'\"'$IF'\"'\"',\"not_found\":true}'; continue; fi\n")
		b.WriteString("OPER=$(cat \"/sys/class/net/$IF/operstate\" 2>/dev/null || echo unknown)\n")
		b.WriteString("RXB=$(get \"$BASE/rx_bytes\"); TXB=$(get \"$BASE/tx_bytes\"); ")
		b.WriteString("RXP=$(get \"$BASE/rx_packets\"); TXP=$(get \"$BASE/tx_packets\"); ")
		b.WriteString("RXD=$(get \"$BASE/rx_dropped\"); TXD=$(get \"$BASE/tx_dropped\");\n")
		b.WriteString("printf '{\"if\":\"%s\",\"oper\":\"%s\",\"rx_bytes\":%s,\"tx_bytes\":%s,\"rx_packets\":%s,\"tx_packets\":%s,\"rx_dropped\":%s,\"tx_dropped\":%s}\\n' \"$IF\" \"$OPER\" \"$RXB\" \"$TXB\" \"$RXP\" \"$TXP\" \"$RXD\" \"$TXD\"\n")
	}
	return b.String()
}
