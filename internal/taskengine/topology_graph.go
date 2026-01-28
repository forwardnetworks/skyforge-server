package taskengine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type TopologyGraph struct {
	GeneratedAt string         `json:"generatedAt,omitempty"`
	Source      string         `json:"source"`
	Nodes       []TopologyNode `json:"nodes"`
	Edges       []TopologyEdge `json:"edges"`
}

type TopologyNode struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Kind     string `json:"kind,omitempty"`
	MgmtIP   string `json:"mgmtIp,omitempty"`   // pod IP (for ping/debug)
	MgmtHost string `json:"mgmtHost,omitempty"` // service DNS (for TCP/UDP mgmt)
	PingIP   string `json:"pingIp,omitempty"`   // explicit ping target (usually pod IP)
	Status   string `json:"status,omitempty"`
}

type TopologyEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
}

func containerlabLabBytesToTopologyGraph(raw []byte) (*TopologyGraph, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("containerlab lab payload empty")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("containerlab lab payload invalid: %w", err)
	}

	graph := &TopologyGraph{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      "containerlab",
		Nodes:       nil,
		Edges:       nil,
	}

	nodesRaw, _ := decoded["nodes"]
	graph.Nodes = parseContainerlabNodes(nodesRaw)
	graph.Edges = parseContainerlabLinks(decoded["links"], decoded["edges"])

	if len(graph.Nodes) == 0 {
		// Some API responses nest under "lab" or "topology".
		if lab, ok := decoded["lab"].(map[string]any); ok {
			graph.Nodes = parseContainerlabNodes(lab["nodes"])
			graph.Edges = parseContainerlabLinks(lab["links"], lab["edges"])
		}
		if topo, ok := decoded["topology"].(map[string]any); ok && len(graph.Nodes) == 0 {
			graph.Nodes = parseContainerlabNodes(topo["nodes"])
			graph.Edges = parseContainerlabLinks(topo["links"], topo["edges"])
		}
	}

	return graph, nil
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
	default:
		return out
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
			if s, ok := raw.(string); ok {
				if strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
				continue
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
	ip := getStr(
		"mgmt_ipv4",
		"mgmt_ipv4_address",
		"mgmtIPv4",
		"mgmtIp",
		"mgmt_ip",
		"ipv4",
		"ip",
	)
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
		src := strings.TrimSpace(firstString(m, "a_node", "source", "src", "from"))
		dst := strings.TrimSpace(firstString(m, "b_node", "target", "dst", "to"))
		if src == "" || dst == "" {
			// Common containerlab shape: endpoints like "n1:eth1".
			a := strings.TrimSpace(firstString(m, "a", "endpoint_a", "a_endpoint"))
			b := strings.TrimSpace(firstString(m, "b", "endpoint_b", "b_endpoint"))
			src = strings.Split(a, ":")[0]
			dst = strings.Split(b, ":")[0]
		}
		if src == "" || dst == "" {
			continue
		}
		label := strings.TrimSpace(firstString(m, "label", "name"))
		id := strings.TrimSpace(firstString(m, "id"))
		if id == "" {
			id = fmt.Sprintf("e-%d", idx)
		}
		edges = append(edges, TopologyEdge{
			ID:     id,
			Source: src,
			Target: dst,
			Label:  label,
		})
	}
	return edges
}

func firstString(m map[string]any, keys ...string) string {
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
