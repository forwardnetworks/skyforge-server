package taskengine

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func containerlabYAMLBytesToTopologyGraph(raw []byte, podInfo map[string]TopologyNode) (*TopologyGraph, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("containerlab yaml is empty")
	}
	var decoded map[string]any
	if err := yaml.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("failed to parse containerlab yaml: %w", err)
	}
	topologyAny, ok := decoded["topology"].(map[string]any)
	if !ok || topologyAny == nil {
		return nil, fmt.Errorf("containerlab yaml missing topology")
	}

	nodes := parseContainerlabNodes(topologyAny["nodes"])
	defaultKind := ""
	if defaults, ok := topologyAny["defaults"].(map[string]any); ok && defaults != nil {
		defaultKind = strings.TrimSpace(firstString(defaults, "kind", "type", "imageKind"))
	}
	if defaultKind != "" {
		for i := range nodes {
			if strings.TrimSpace(nodes[i].Kind) == "" {
				nodes[i].Kind = defaultKind
			}
		}
	}
	edges := parseContainerlabYAMLLinks(topologyAny["links"])

	if len(nodes) == 0 {
		return nil, fmt.Errorf("containerlab yaml missing nodes")
	}

	if len(podInfo) > 0 {
		for i := range nodes {
			key := strings.TrimSpace(nodes[i].ID)
			if key == "" {
				continue
			}
			if info, ok := podInfo[key]; ok {
				if strings.TrimSpace(info.MgmtIP) != "" {
					nodes[i].MgmtIP = strings.TrimSpace(info.MgmtIP)
				}
				if strings.TrimSpace(info.MgmtHost) != "" {
					nodes[i].MgmtHost = strings.TrimSpace(info.MgmtHost)
				}
				if strings.TrimSpace(info.PingIP) != "" {
					nodes[i].PingIP = strings.TrimSpace(info.PingIP)
				}
				if strings.TrimSpace(info.Status) != "" {
					nodes[i].Status = strings.TrimSpace(info.Status)
				}
			}
		}
	}

	return &TopologyGraph{
		Source: "clabernetes",
		Nodes:  nodes,
		Edges:  edges,
	}, nil
}

func parseContainerlabYAMLLinks(raw any) []TopologyEdge {
	out := []TopologyEdge{}
	arr, ok := raw.([]any)
	if !ok {
		return out
	}
	for idx, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		src, dst := "", ""
		if endpointsAny, ok := m["endpoints"]; ok {
			if endpoints, ok := endpointsAny.([]any); ok && len(endpoints) >= 2 {
				a := strings.TrimSpace(fmt.Sprintf("%v", endpoints[0]))
				b := strings.TrimSpace(fmt.Sprintf("%v", endpoints[1]))
				src = strings.SplitN(a, ":", 2)[0]
				dst = strings.SplitN(b, ":", 2)[0]
			}
		}
		if strings.TrimSpace(src) == "" || strings.TrimSpace(dst) == "" {
			// Fall back to the API-shaped parsing (a_node/b_node, a/b, etc.).
			src = strings.TrimSpace(firstString(m, "a_node", "source", "src", "from"))
			dst = strings.TrimSpace(firstString(m, "b_node", "target", "dst", "to"))
			if src == "" || dst == "" {
				a := strings.TrimSpace(firstString(m, "a", "endpoint_a", "a_endpoint"))
				b := strings.TrimSpace(firstString(m, "b", "endpoint_b", "b_endpoint"))
				src = strings.SplitN(a, ":", 2)[0]
				dst = strings.SplitN(b, ":", 2)[0]
			}
		}
		if src == "" || dst == "" {
			continue
		}
		label := strings.TrimSpace(firstString(m, "label", "name"))
		id := strings.TrimSpace(firstString(m, "id"))
		if id == "" {
			id = fmt.Sprintf("e-%d", idx)
		}
		out = append(out, TopologyEdge{
			ID:     id,
			Source: src,
			Target: dst,
			Label:  label,
		})
	}
	return out
}
