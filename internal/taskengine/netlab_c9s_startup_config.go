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

	modified := false

	for node, nodeAny := range nodesAny {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}

		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		image := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))

		// vrnetlab qemu-based nodes use /config/startup-config.cfg as the loadable startup config.
		// Keep IOS-family and Junos-family out of the startup-config injection path to
		// match the native netlab/containerlab + vrnetlab workflow:
		// - vrnetlab bootstraps the device with baseline SSH enabled
		// - Skyforge gates on SSH readiness and then runs netlab initial (when enabled)
		//
		// Injecting a partial netlab snippet as "startup-config" can accidentally disable
		// SSH (no banner) and/or diverge from netlab's own apply logic, so we only inject
		// startup-config for platforms where we explicitly want containerlab-style boot
		// config mounting (for example, EOS/cEOS handled elsewhere).
		if !strings.Contains(image, "/vrnetlab/") {
			continue
		}
		if kind == "cisco_iol" || kind == "cisco_ioll2" {
			continue
		}
		if isVrnetlabIOSFamily(kind, image) {
			// Native hard-cut: do not mutate old image tags here.
			// Only ensure startup-config is not injected for IOS-family vrnetlab nodes.
			if _, ok := cfg["startup-config"]; ok {
				delete(cfg, "startup-config")
				modified = true
			}
			nodesAny[node] = cfg
			continue
		}
		if isVrnetlabASAFamily(kind, image) {
			// ASAv behaves like other vrnetlab images where we prefer baseline boot + SSH
			// readiness instead of injecting partial startup snippets.
			if _, ok := cfg["startup-config"]; ok {
				delete(cfg, "startup-config")
				modified = true
			}
			nodesAny[node] = cfg
			continue
		}
		if isVrnetlabJunosFamily(kind, image) {
			// Ensure the generated topology does not reference a startup-config file we
			// are not going to mount/inject.
			if _, ok := cfg["startup-config"]; ok {
				delete(cfg, "startup-config")
				modified = true
			}
			nodesAny[node] = cfg
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
		combined = stripNetlabJunosDeleteDirectives(kind, combined)
		combined = normalizeNetlabJunosHierarchicalConfig(kind, combined)

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
		if modified {
			out, err := yaml.Marshal(topo)
			if err != nil {
				return nil, nil, err
			}
			return out, nodeMounts, nil
		}
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

func isVrnetlabASAFamily(kind, image string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	image = strings.ToLower(strings.TrimSpace(image))
	return kind == "asav" || strings.Contains(image, "asav")
}

func isVrnetlabIOSFamily(kind, image string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	image = strings.ToLower(strings.TrimSpace(image))
	return kind == "cisco_vios" || kind == "cisco_viosl2" || kind == "vr-csr" || kind == "cisco_c8000v" ||
		strings.Contains(image, "/cisco_vios") || strings.Contains(image, "/cisco_viosl2") ||
		strings.Contains(image, "/vr-csr") || strings.Contains(image, "/cisco_c8000v")
}

func isVrnetlabJunosFamily(kind, image string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	image = strings.ToLower(strings.TrimSpace(image))

	if kind == "vr-vmx" || kind == "vr-vsrx" {
		return true
	}
	if strings.Contains(kind, "junos") || strings.Contains(kind, "vjunos") || strings.Contains(kind, "vqfx") || strings.Contains(kind, "vsrx") {
		return true
	}
	// Match on common vrnetlab Juniper image names.
	if strings.Contains(image, "/juniper_") || strings.Contains(image, "/vr-vmx") || strings.Contains(image, "/juniper_vsrx") {
		return true
	}
	return false
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
