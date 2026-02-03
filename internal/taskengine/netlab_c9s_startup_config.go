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

	const startupPath = "/config/startup-config.cfg"
	mountedCount := 0

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

		// For vrnetlab nodes, do not concatenate netlab snippets (node_files). Instead,
		// rely on netlab's generated startup configs (workdir/config/<node>.cfg) and
		// mount them into the vrnetlab container at /config/startup-config.cfg.
		//
		// This keeps netlab as the source-of-truth for ordering/merging and avoids
		// subtle syntax issues that can arise when recombining fragments.
		expectedConfigName := fmt.Sprintf("%s.cfg", nodeName)
		var startupCfg c9sFileFromConfigMap
		found := false
		for _, m := range nodeMounts[nodeName] {
			if strings.TrimSpace(m.ConfigMapName) == "" || strings.TrimSpace(m.ConfigMapPath) == "" {
				continue
			}
			if strings.TrimSpace(m.ConfigMapPath) != expectedConfigName {
				continue
			}
			if !strings.Contains(m.FilePath, "/config/") {
				continue
			}
			startupCfg = m
			found = true
			break
		}
		if !found {
			return nil, nil, fmt.Errorf("netlab did not produce startup config for %s (expected config/%s)", nodeName, expectedConfigName)
		}

		cfg["startup-config"] = startupPath
		nodesAny[node] = cfg

		nodeMounts[nodeName] = upsertC9sMount(nodeMounts[nodeName], c9sFileFromConfigMap{
			ConfigMapName: startupCfg.ConfigMapName,
			ConfigMapPath: startupCfg.ConfigMapPath,
			FilePath:      startupPath,
			Mode:          "read",
		})
		mountedCount++
	}

	if mountedCount > 0 {
		log.Infof("c9s: vrnetlab startup-config mounted from netlab config/: nodes=%d", mountedCount)
	}

	topology["nodes"] = nodesAny
	topo["topology"] = topology
	out, err := yaml.Marshal(topo)
	if err != nil {
		return nil, nil, fmt.Errorf("encode clab.yml: %w", err)
	}

	return out, nodeMounts, nil
}

func stripNetlabJunosDeleteDirectives(kind, startupConfig string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	startupConfig = strings.ReplaceAll(startupConfig, "\r\n", "\n")
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(startupConfig) == "" {
		return startupConfig
	}

	// netlab Junos templates contain `delete:` pseudo-directives intended for idempotent CLI execution.
	// Those lines are not valid Junos configuration syntax and will make `load merge terminal` fail.
	//
	// Stripping them is safe for Skyforge, as labs are typically deployed from a clean slate.
	if !(kind == "vr-vmx" || strings.Contains(kind, "junos") || strings.Contains(kind, "vqfx") || strings.Contains(kind, "vsrx") || strings.Contains(kind, "vjunos")) {
		return startupConfig
	}

	in := strings.Split(startupConfig, "\n")
	out := make([]string, 0, len(in))
	for _, line := range in {
		if strings.HasPrefix(strings.TrimSpace(line), "delete:") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func normalizeNetlabJunosHierarchicalConfig(kind, startupConfig string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	startupConfig = strings.ReplaceAll(startupConfig, "\r\n", "\n")
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(startupConfig) == "" {
		return startupConfig
	}
	if !(kind == "vr-vmx" || strings.Contains(kind, "junos") || strings.Contains(kind, "vqfx") || strings.Contains(kind, "vsrx") || strings.Contains(kind, "vjunos")) {
		return startupConfig
	}
	// Only attempt to normalize hierarchical (brace) syntax.
	if !strings.Contains(startupConfig, "{") {
		return startupConfig
	}

	junosIfaceUnits := collectJunosInterfaceUnits(startupConfig)

	in := strings.Split(startupConfig, "\n")
	out := make([]string, 0, len(in))

	for i := 0; i < len(in); i++ {
		line := in[i]
		trimmed := strings.TrimSpace(line)

		// netlab can occasionally emit `router-id X` without a trailing semicolon in hierarchical config.
		if strings.HasPrefix(trimmed, "router-id ") && !strings.HasSuffix(trimmed, ";") {
			out = append(out, line+";")
			continue
		}

		// netlab can emit an interface list split across lines:
		//
		// interface [
		//   ge-0/0/0.0
		// ];
		//
		// and in some cases it is empty (which Junos rejects). Normalize it to a
		// single-line list. If the list is empty, populate it with interface units
		// found under `interfaces { ... }` so that BGP export policies remain meaningful.
		if strings.HasPrefix(trimmed, "interface [") {
			indent := line[:strings.Index(line, "interface")]

			j := i + 1
			entries := make([]string, 0, 8)
			for ; j < len(in); j++ {
				t := strings.TrimSpace(in[j])
				if t == "];" {
					break
				}
				if t == "" {
					continue
				}
				entries = append(entries, strings.Fields(t)...)
			}

			// If the bracket list exists but contains no entries, fall back to the
			// interfaces present in the same config.
			if len(entries) == 0 && len(junosIfaceUnits) > 0 {
				entries = append(entries, junosIfaceUnits...)
			}

			// Only emit the line if we have something reasonable to put in it.
			if len(entries) > 0 {
				out = append(out, indent+"interface [ "+strings.Join(entries, " ")+" ];")
			}

			// Skip all lines up to and including the closing "];" line.
			if j < len(in) {
				i = j
			}
			continue
		}

		out = append(out, line)
	}

	return strings.Join(out, "\n")
}

func collectJunosInterfaceUnits(startupConfig string) []string {
	startupConfig = strings.ReplaceAll(startupConfig, "\r\n", "\n")
	lines := strings.Split(startupConfig, "\n")

	seen := map[string]bool{}
	out := make([]string, 0, 8)

	inInterfaces := false
	braceDepth := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Track entry into the `interfaces { ... }` block.
		if !inInterfaces && trimmed == "interfaces {" {
			inInterfaces = true
			braceDepth = 1
			continue
		}

		if inInterfaces {
			// Capture interface unit headers like `ge-0/0/0.0 {` and `lo0.0 {`.
			if idx := strings.Index(trimmed, "{"); idx > 0 {
				left := strings.TrimSpace(trimmed[:idx])
				if strings.Contains(left, ".") && !strings.Contains(left, " ") && !seen[left] {
					seen[left] = true
					out = append(out, left)
				}
			}

			// Update brace depth; once it drops to 0 we are out of `interfaces`.
			braceDepth += strings.Count(line, "{")
			braceDepth -= strings.Count(line, "}")
			if braceDepth <= 0 {
				inInterfaces = false
			}
		}
	}

	sort.Strings(out)
	return out
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
		// netlab typically emits Junos config in "curly brace" format. Avoid mixing `set` and
		// bracketed syntax; instead, inject an additional `snmp { ... }` block.
		if strings.Contains(startupConfig, "{") {
			snippet = "snmp {\n  community public {\n    authorization read-only;\n  }\n}\n"
		} else {
			// Fallback: set-style config (safe for many Junos CLIs).
			snippet = "set snmp community public authorization read-only\n"
		}
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
