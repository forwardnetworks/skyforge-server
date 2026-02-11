package taskengine

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type containerlabNodeSpec struct {
	Kind  string
	Image string
}

// containerlabNodeSpecs parses a containerlab YAML document and returns a mapping of
// nodeName -> (kind, image) for nodes under topology.nodes.
func containerlabNodeSpecs(containerlabYAML string) (map[string]containerlabNodeSpec, error) {
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

	out := map[string]containerlabNodeSpec{}
	for nodeName, nodeAny := range nodes {
		nodeName = strings.TrimSpace(nodeName)
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		image := strings.TrimSpace(fmt.Sprintf("%v", cfg["image"]))
		out[nodeName] = containerlabNodeSpec{
			Kind:  kind,
			Image: image,
		}
	}
	return out, nil
}

// containerlabNodeKinds parses a containerlab YAML document and returns a mapping of
// nodeName -> kind for nodes under topology.nodes.
func containerlabNodeKinds(containerlabYAML string) (map[string]string, error) {
	specs, err := containerlabNodeSpecs(containerlabYAML)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, nil
	}

	out := map[string]string{}
	for nodeName, spec := range specs {
		kind := strings.TrimSpace(spec.Kind)
		if kind == "" {
			continue
		}
		out[nodeName] = kind
	}
	return out, nil
}
