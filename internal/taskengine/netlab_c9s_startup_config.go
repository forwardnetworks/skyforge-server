package taskengine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// injectNetlabC9sStartupConfig injects startup-config files for NOS containers that need them
// in clabernetes native mode. This is a best-effort adaptation layer that keeps netlab as the
// source of truth while making generated topologies runnable in Kubernetes.
//
// Current behavior:
// - EOS/cEOS: use the existing EOS-specific startup-config injection (with SSH/user helpers).
// - vrnetlab (qemu-based) NOS images: mount combined netlab snippets into /config/startup-config.cfg.
func injectNetlabC9sStartupConfig(
	ctx context.Context,
	ns, topologyName string,
	topologyYAML []byte,
	nodeMounts map[string][]c9sFileFromConfigMap,
	log Logger,
) ([]byte, map[string][]c9sFileFromConfigMap, error) {
	// Preserve existing EOS behavior.
	out, nodeMountsOut, err := injectNetlabC9sEOSStartupConfig(ctx, ns, topologyName, topologyYAML, nodeMounts, log)
	if err != nil {
		return nil, nil, err
	}

	return injectNetlabC9sVrnetlabStartupConfig(ctx, ns, topologyName, out, nodeMountsOut, log)
}

func injectNetlabC9sVrnetlabStartupConfig(
	ctx context.Context,
	ns, topologyName string,
	topologyYAML []byte,
	nodeMounts map[string][]c9sFileFromConfigMap,
	log Logger,
) ([]byte, map[string][]c9sFileFromConfigMap, error) {
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

	overrideCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-vrnetlab-startup", topologyName), "c9s-vrnetlab-startup")
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
		"firewall.zonebased",
	}

	const startupPath = "/config/startup-config.cfg"

	for node, nodeAny := range nodesAny {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}

		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		image := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))

		// vrnetlab qemu-based nodes use /config/startup-config.cfg as the loadable startup config.
		// Keep IOS/IOL out of this path; their bootstrap is handled differently.
		if !strings.Contains(image, "/vrnetlab/") {
			continue
		}
		if kind == "cisco_iol" || kind == "cisco_ioll2" {
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
			log.Infof("c9s: vrnetlab startup-config skipped (no node configmap): %s", nodeName)
			continue
		}

		data, ok, err := kubeGetConfigMap(ctx, ns, cmName)
		if err != nil {
			return nil, nil, err
		}
		if !ok || len(data) == 0 {
			log.Infof("c9s: vrnetlab startup-config skipped (empty configmap): %s", cmName)
			continue
		}

		combined := combineNetlabSnippets(data, knownOrder)
		if strings.TrimSpace(combined) == "" {
			log.Infof("c9s: vrnetlab startup-config skipped (no snippets): %s", nodeName)
			continue
		}
		combined = appendDefaultSNMPPublic(kind, combined)

		key := sanitizeArtifactKeySegment(fmt.Sprintf("%s-startup-config.cfg", nodeName))
		if key == "" || key == "unknown" {
			key = "startup-config.cfg"
		}
		overrideData[key] = combined

		// Set startup-config path in topology for clarity (mount is handled by FilesFromConfigMap).
		cfg["startup-config"] = startupPath
		nodesAny[node] = cfg

		// Ensure the file is mounted into the NOS container at the path vrnetlab expects.
		nodeMounts[nodeName] = upsertC9sMount(nodeMounts[nodeName], c9sFileFromConfigMap{
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
	log.Infof("c9s: vrnetlab startup-config injected: nodes=%d", len(overrideData))

	topology["nodes"] = nodesAny
	topo["topology"] = topology
	out, err := yaml.Marshal(topo)
	if err != nil {
		return nil, nil, fmt.Errorf("encode clab.yml: %w", err)
	}

	return out, nodeMounts, nil
}

func appendDefaultSNMPPublic(kind, startupConfig string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	startupConfig = strings.ReplaceAll(startupConfig, "\r\n", "\n")
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(startupConfig) == "" {
		return startupConfig
	}

	// If the topology already contains SNMP config, don't inject defaults.
	if strings.Contains(strings.ToLower(startupConfig), "snmp") {
		return startupConfig
	}

	snippet := ""
	switch {
	case kind == "vr-vmx" ||
		strings.Contains(kind, "junos") ||
		strings.Contains(kind, "vqfx") ||
		strings.Contains(kind, "vsrx") ||
		strings.Contains(kind, "vjunos"):
		// Junos accepts `set` commands in configuration mode.
		snippet = "set snmp community public authorization read-only\n"
	case strings.Contains(kind, "n9kv") || strings.Contains(kind, "nxos"):
		// NX-OS supports v2c community strings, but uses role-based groups.
		snippet = "snmp-server community public group network-operator\n"
	case strings.Contains(kind, "ios") ||
		strings.Contains(kind, "csr") ||
		strings.Contains(kind, "c8000") ||
		strings.Contains(kind, "cat8000"):
		snippet = "snmp-server community public ro\n"
	case strings.Contains(kind, "eos") || strings.Contains(kind, "veos"):
		snippet = "snmp-server community public ro\n"
	}

	if strings.TrimSpace(snippet) == "" {
		return startupConfig
	}

	if !strings.HasSuffix(startupConfig, "\n") {
		startupConfig += "\n"
	}

	return startupConfig + snippet
}

func combineNetlabSnippets(data map[string]string, knownOrder []string) string {
	if len(data) == 0 {
		return ""
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
	extras := make([]string, 0, len(data))
	for k := range data {
		if seen[k] {
			continue
		}
		if strings.TrimSpace(k) == "" {
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
		return ""
	}
	combined := strings.Join(parts, "\n")
	combined = strings.ReplaceAll(combined, "\r\n", "\n")
	if !strings.HasSuffix(combined, "\n") {
		combined += "\n"
	}
	return combined
}

func upsertC9sMount(existing []c9sFileFromConfigMap, mount c9sFileFromConfigMap) []c9sFileFromConfigMap {
	if strings.TrimSpace(mount.FilePath) == "" {
		return existing
	}
	for i := range existing {
		if strings.TrimSpace(existing[i].FilePath) == strings.TrimSpace(mount.FilePath) {
			existing[i] = mount
			return existing
		}
	}
	return append(existing, mount)
}
