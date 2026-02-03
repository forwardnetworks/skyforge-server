package taskengine

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// containerlabNodeKinds parses a containerlab YAML document and returns a mapping of
// nodeName -> kind for nodes under topology.nodes.
func containerlabNodeKinds(containerlabYAML string) (map[string]string, error) {
	containerlabYAML = strings.TrimSpace(containerlabYAML)
	if containerlabYAML == "" {
		return nil, nil
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(containerlabYAML), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse containerlab yaml: %w", err)
	}
	if doc == nil {
		return nil, nil
	}
	topology, ok := doc["topology"].(map[string]any)
	if !ok || topology == nil {
		return nil, nil
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || nodes == nil {
		return nil, nil
	}

	out := map[string]string{}
	for nodeName, nodeAny := range nodes {
		nodeName = strings.TrimSpace(nodeName)
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind == "" {
			continue
		}
		out[nodeName] = kind
	}
	return out, nil
}
