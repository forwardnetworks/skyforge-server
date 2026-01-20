package taskengine

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func injectNetlabC9sEOSStartupConfig(ctx context.Context, ns, topologyName string, topologyYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, log Logger) ([]byte, map[string][]c9sFileFromConfigMap, error) {
	if log == nil {
		log = noopLogger{}
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" || len(topologyYAML) == 0 || nodeMounts == nil {
		return topologyYAML, nodeMounts, nil
	}

	var topo map[string]any
	if err := yaml.Unmarshal(topologyYAML, &topo); err != nil {
		return nil, nil, fmt.Errorf("parse clab.yml: %w", err)
	}
	topology, _ := topo["topology"].(map[string]any)
	nodesAny, _ := topology["nodes"].(map[string]any)
	if len(nodesAny) == 0 {
		return topologyYAML, nodeMounts, nil
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	overrideCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-eos-startup", topologyName), "c9s-eos-startup")
	overrideData := map[string]string{}
	labels := map[string]string{"skyforge-c9s-topology": topologyName}

	knownOrder := []string{
		"normalize",
		"initial",
		"vlan",
		"bgp",
		"vxlan",
		"evpn",
		"ebgp_ecmp",
		"ebgp.ecmp",
	}

	for node, nodeAny := range nodesAny {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind != "eos" && kind != "ceos" {
			continue
		}

		// Find the netlab-generated snippet ConfigMap for this node (from mounts).
		cmName := ""
		if mounts, ok := nodeMounts[nodeName]; ok {
			for _, m := range mounts {
				if strings.TrimSpace(m.ConfigMapName) != "" {
					cmName = strings.TrimSpace(m.ConfigMapName)
					break
				}
			}
		}
		if cmName == "" {
			log.Infof("c9s: eos startup-config skipped (no node configmap): %s", nodeName)
			continue
		}

		data, ok, err := kubeGetConfigMap(ctx, ns, cmName)
		if err != nil {
			return nil, nil, err
		}
		if !ok || len(data) == 0 {
			log.Infof("c9s: eos startup-config skipped (empty configmap): %s", cmName)
			continue
		}

		parts := make([]string, 0, 8)
		seen := map[string]bool{}
		for _, k := range knownOrder {
			v := strings.TrimSpace(data[k])
			if v == "" {
				continue
			}
			parts = append(parts, v)
			seen[k] = true
		}
		extras := make([]string, 0)
		for k := range data {
			if seen[k] {
				continue
			}
			// Skip non-config entries
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "":
				continue
			}
			v := strings.TrimSpace(data[k])
			if v == "" {
				continue
			}
			extras = append(extras, k)
		}
		sort.Strings(extras)
		for _, k := range extras {
			parts = append(parts, strings.TrimSpace(data[k]))
		}

		if len(parts) == 0 {
			log.Infof("c9s: eos startup-config skipped (no snippets): %s", nodeName)
			continue
		}

		combined := strings.Join(parts, "\n")
		combined = strings.ReplaceAll(combined, "\r\n", "\n")
		if !strings.HasSuffix(combined, "\n") {
			combined += "\n"
		}
		if !strings.Contains(strings.ToLower(combined), "\nend\n") {
			combined += "end\n"
		}
		combined, _ = injectEOSManagementSSH(combined)
		combined, _ = injectEOSDefaultSSHUser(combined)

		key := sanitizeArtifactKeySegment(fmt.Sprintf("%s-startup.cfg", nodeName))
		if key == "" || key == "unknown" {
			key = "startup.cfg"
		}
		overrideData[key] = combined

		startupPath := path.Join(mountRoot, "config", key)
		cfg["startup-config"] = startupPath
		nodesAny[node] = cfg

		// Ensure the startup-config file is mounted (launcher reads it during deploy).
		nodeMounts[nodeName] = append(nodeMounts[nodeName], c9sFileFromConfigMap{
			ConfigMapName: overrideCM,
			ConfigMapPath: key,
			FilePath:      startupPath,
			Mode:          "read",
		})
	}

	if len(overrideData) == 0 {
		return topologyYAML, nodeMounts, nil
	}
	if err := kubeUpsertConfigMap(ctx, ns, overrideCM, overrideData, labels); err != nil {
		return nil, nil, err
	}
	log.Infof("c9s: eos startup-config injected: nodes=%d", len(overrideData))

	topology["nodes"] = nodesAny
	topo["topology"] = topology
	out, err := yaml.Marshal(topo)
	if err != nil {
		return nil, nil, fmt.Errorf("encode clab.yml: %w", err)
	}
	return out, nodeMounts, nil
}
