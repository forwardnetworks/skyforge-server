package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type DeploymentTopologyResponse struct {
	GeneratedAt string         `json:"generatedAt"`
	Source      string         `json:"source"`
	Nodes       []TopologyNode `json:"nodes"`
	Edges       []TopologyEdge `json:"edges"`
	ArtifactKey string         `json:"artifactKey,omitempty"`
}

type TopologyNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind,omitempty"`
	MgmtIP string `json:"mgmtIp,omitempty"`
	Status string `json:"status,omitempty"`
}

type TopologyEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	SourceIf string `json:"sourceIf,omitempty"`
	TargetIf string `json:"targetIf,omitempty"`
	Label    string `json:"label,omitempty"`
}

// GetWorkspaceDeploymentTopology returns a lightweight, provider-derived topology view.
//
// For containerlab, the topology is sourced from the containerlab API after deploy so we
// can reflect the resolved management IPs.
//
//encore:api auth method=GET path=/api/users/:id/deployments/:deploymentID/topology
func (s *Service) GetWorkspaceDeploymentTopology(ctx context.Context, id, deploymentID string) (*DeploymentTopologyResponse, error) {
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
	dep, err := s.getWorkspaceDeployment(ctx, pc.userScope.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	switch dep.Type {
	case "containerlab":
		return s.getContainerlabDeploymentTopology(ctx, pc, dep)
	case "netlab-c9s":
		return s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, "netlab-c9s-run")
	case "clabernetes":
		return s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, "clabernetes-run")
	case "eve_ng":
		return s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, "eve-ng-run")
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topology is not available for this deployment type").Err()
	}
}

func (s *Service) getDeploymentTopologyFromLatestTaskArtifact(ctx context.Context, pc *userContext, dep *UserScopeDeployment, taskType string) (*DeploymentTopologyResponse, error) {
	taskType = strings.TrimSpace(taskType)
	if taskType == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("task type is required").Err()
	}
	if task, err := getLatestDeploymentTask(ctx, s.db, pc.userScope.ID, dep.ID, taskType); err == nil && task != nil {
		key := strings.TrimSpace(getJSONMapString(task.Metadata, "topologyKey"))
		if key != "" {
			ctxRead, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if raw, err := readWorkspaceArtifact(ctxRead, s.cfg, pc.userScope.ID, key, 2<<20); err == nil && len(raw) > 0 {
				if graph, err := parseTopologyGraph(raw); err == nil && graph != nil {
					graph.ArtifactKey = key
					return graph, nil
				}
			}
		}
	}
	return nil, errs.B().Code(errs.Unavailable).Msg("topology is not available yet for this deployment").Err()
}

func (s *Service) getContainerlabDeploymentTopology(ctx context.Context, pc *userContext, dep *UserScopeDeployment) (*DeploymentTopologyResponse, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	netlabServer, _ := cfgAny["netlabServer"].(string)
	netlabServer = strings.TrimSpace(netlabServer)
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}
	server, err := s.resolveContainerlabServerConfig(ctx, pc, netlabServer)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}
	apiURL := containerlabAPIURL(s.cfg, *server)
	if apiURL == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("containerlab api url is not configured").Err()
	}
	labName, _ := cfgAny["labName"].(string)
	labName = strings.TrimSpace(labName)
	if labName == "" {
		labName = containerlabLabName(pc.userScope.Slug, dep.Name)
	}

	// Prefer the last computed topology artifact (stored by the worker post-deploy).
	if task, err := getLatestDeploymentTask(ctx, s.db, pc.userScope.ID, dep.ID, "containerlab-run"); err == nil && task != nil {
		key := strings.TrimSpace(getJSONMapString(task.Metadata, "topologyKey"))
		if key != "" {
			ctxRead, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if raw, err := readWorkspaceArtifact(ctxRead, s.cfg, pc.userScope.ID, key, 2<<20); err == nil && len(raw) > 0 {
				if graph, err := parseTopologyGraph(raw); err == nil && graph != nil {
					graph.ArtifactKey = key
					return graph, nil
				}
			}
		}
	}

	// Fallback: query containerlab live.
	token, err := containerlabTokenForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab auth is not configured").Err()
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	getResp, body, err := containerlabAPIGet(checkCtx, fmt.Sprintf("%s/api/v1/labs/%s", apiURL, labName), token, containerlabSkipTLS(s.cfg, *server))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach containerlab api").Err()
	}
	if getResp.StatusCode == http.StatusNotFound {
		return nil, errs.B().Code(errs.NotFound).Msg("lab not found").Err()
	}
	if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg(strings.TrimSpace(string(body))).Err()
	}

	graph, err := containerlabLabBytesToTopologyGraph(body)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg(err.Error()).Err()
	}
	graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return graph, nil
}

func parseTopologyGraph(raw []byte) (*DeploymentTopologyResponse, error) {
	var g DeploymentTopologyResponse
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	if len(g.Nodes) == 0 {
		return nil, fmt.Errorf("empty topology")
	}
	return &g, nil
}

func containerlabLabBytesToTopologyGraph(raw []byte) (*DeploymentTopologyResponse, error) {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("containerlab lab payload invalid")
	}
	nodes := parseContainerlabNodes(decoded["nodes"])
	edges := parseContainerlabLinks(decoded["links"], decoded["edges"])
	if len(nodes) == 0 {
		if lab, ok := decoded["lab"].(map[string]any); ok {
			nodes = parseContainerlabNodes(lab["nodes"])
			edges = parseContainerlabLinks(lab["links"], lab["edges"])
		}
	}
	return &DeploymentTopologyResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      "containerlab",
		Nodes:       nodes,
		Edges:       edges,
	}, nil
}

func parseContainerlabNodes(raw any) []TopologyNode {
	out := []TopologyNode{}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, containerlabNodeFromMap(m))
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			m, ok := v[key].(map[string]any)
			if !ok {
				continue
			}
			node := containerlabNodeFromMap(m)
			if node.ID == "" {
				node.ID = key
			}
			if node.Label == "" {
				node.Label = key
			}
			out = append(out, node)
		}
	}
	filtered := make([]TopologyNode, 0, len(out))
	for _, n := range out {
		n.ID = strings.TrimSpace(n.ID)
		if n.ID == "" {
			continue
		}
		if strings.TrimSpace(n.Label) == "" {
			n.Label = n.ID
		}
		filtered = append(filtered, n)
	}
	return filtered
}

func containerlabNodeFromMap(m map[string]any) TopologyNode {
	getStr := func(keys ...string) string {
		for _, key := range keys {
			raw, ok := m[key]
			if !ok {
				continue
			}
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
			if raw != nil {
				val := strings.TrimSpace(fmt.Sprintf("%v", raw))
				if val != "" {
					return val
				}
			}
		}
		return ""
	}
	name := getStr("name", "nodeName", "hostname", "id")
	kind := getStr("kind", "type", "imageKind")
	status := getStr("status", "state")
	ip := getStr("mgmt_ipv4", "mgmt_ipv4_address", "mgmtIPv4", "mgmtIp", "mgmt_ip", "ipv4", "ip")
	return TopologyNode{
		ID:     name,
		Label:  name,
		Kind:   kind,
		MgmtIP: ip,
		Status: status,
	}
}

func parseContainerlabLinks(primary any, fallback any) []TopologyEdge {
	edges := []TopologyEdge{}
	raw := primary
	if raw == nil {
		raw = fallback
	}
	arr, ok := raw.([]any)
	if !ok {
		return edges
	}
	for idx, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		src := strings.TrimSpace(firstStringValue(m, "a_node", "source", "src", "from"))
		dst := strings.TrimSpace(firstStringValue(m, "b_node", "target", "dst", "to"))
		srcIf := strings.TrimSpace(firstStringValue(m, "a_intf", "a_intf_name", "a_iface", "a_interface", "src_if", "src_intf", "source_if"))
		dstIf := strings.TrimSpace(firstStringValue(m, "b_intf", "b_intf_name", "b_iface", "b_interface", "dst_if", "dst_intf", "target_if"))
		if src == "" || dst == "" {
			a := strings.TrimSpace(firstStringValue(m, "a", "endpoint_a", "a_endpoint"))
			b := strings.TrimSpace(firstStringValue(m, "b", "endpoint_b", "b_endpoint"))
			apart := strings.SplitN(a, ":", 2)
			bpart := strings.SplitN(b, ":", 2)
			src = strings.TrimSpace(apart[0])
			dst = strings.TrimSpace(bpart[0])
			if len(apart) == 2 && srcIf == "" {
				srcIf = strings.TrimSpace(apart[1])
			}
			if len(bpart) == 2 && dstIf == "" {
				dstIf = strings.TrimSpace(bpart[1])
			}
		} else {
			a := strings.TrimSpace(firstStringValue(m, "a", "endpoint_a", "a_endpoint"))
			b := strings.TrimSpace(firstStringValue(m, "b", "endpoint_b", "b_endpoint"))
			apart := strings.SplitN(a, ":", 2)
			bpart := strings.SplitN(b, ":", 2)
			if len(apart) == 2 && strings.TrimSpace(apart[0]) == src && srcIf == "" {
				srcIf = strings.TrimSpace(apart[1])
			}
			if len(bpart) == 2 && strings.TrimSpace(bpart[0]) == dst && dstIf == "" {
				dstIf = strings.TrimSpace(bpart[1])
			}
		}
		if src == "" || dst == "" {
			continue
		}
		label := strings.TrimSpace(firstStringValue(m, "label", "name"))
		if label == "" && srcIf != "" && dstIf != "" {
			label = fmt.Sprintf("%s:%s ↔ %s:%s", src, srcIf, dst, dstIf)
		}
		id := strings.TrimSpace(firstStringValue(m, "id"))
		if id == "" {
			id = fmt.Sprintf("e-%d", idx)
		}
		edges = append(edges, TopologyEdge{
			ID:       id,
			Source:   src,
			Target:   dst,
			SourceIf: srcIf,
			TargetIf: dstIf,
			Label:    label,
		})
	}
	return edges
}

func firstStringValue(m map[string]any, keys ...string) string {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok {
			continue
		}
		if s, ok := raw.(string); ok {
			return s
		}
		if raw != nil {
			return fmt.Sprintf("%v", raw)
		}
	}
	return ""
}
