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
	dpIntfsByNode := countClabDataPlaneInterfaces(topology)

	overrideCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-vrnetlab-startup", topologyName), "c9s-vrnetlab-startup")
	overrideData := map[string]string{}
	labels := map[string]string{"skyforge-c9s-topology": topologyName}
	modified := false

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
		dpIntfs := dpIntfsByNode[nodeName]

		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		image := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))
		device := netlabDeviceKeyForClabNode(kind, image)

		// Only touch vrnetlab images (qemu-based).
		if !strings.Contains(image, "/vrnetlab/") {
			continue
		}

		// Apply QEMU/vrnetlab environment overrides (CLAB_INTFS, virtio-rng, etc) for *all* vrnetlab nodes,
		// even if we don't mount a startup-config for the NOS image.
		applyVrnetlabNodeEnvOverrides(kind, image, dpIntfs, cfg)
		if dpIntfs > 0 {
			modified = true
		}

		// Keep NX-OS on legacy `netlab initial` (Ansible) until native startup/sh support is validated.
		// Remove any startup-config reference/mount so vrnetlab does not apply topology config at boot.
		if device == "nxos" {
			if s, ok := cfg["startup-config"].(string); ok && strings.TrimSpace(s) != "" {
				delete(cfg, "startup-config")
				modified = true
				log.Infof("c9s: nxos startup-config removed (legacy netlab initial path): %s", nodeName)
			}
			dropped := dropC9sMountForPath(nodeMounts[nodeName], startupPath)
			if len(dropped) != len(nodeMounts[nodeName]) {
				modified = true
			}
			nodeMounts[nodeName] = dropped
			nodesAny[node] = cfg
			continue
		}

		// IOSv/IOSvL2 bootstrap SSH internally (vrnetlab's own access_cfg + RSA keygen logic).
		// In the native netlab/containerlab workflow, netlab does NOT mount a full startup-config
		// into IOSv; it applies config post-boot ("netlab initial"). Mounting snippets into
		// /config/startup-config.cfg can wedge IOSv bootstrapping and prevent the SSH server from
		// ever emitting a banner (TCP accept works, but no "SSH-" line), which breaks readiness.
		//
		// Therefore:
		// - do NOT mount the full netlab-generated startup-config (it can wedge bootstrap)
		// - mount a minimal SSH bootstrap-only startup-config so SSH becomes reachable
		// - rewrite to our tuned vrnetlab tags (still vrnetlab-native behavior; just more reliable in k8s)
		if kind == "cisco_vios" || kind == "cisco_viosl2" {
			// Remove any existing startup-config reference + mount first to avoid applying
			// a full netlab-generated config at boot.
			if s, ok := cfg["startup-config"].(string); ok && strings.TrimSpace(s) != "" {
				delete(cfg, "startup-config")
				modified = true
			}
			dropped := dropC9sMountForPath(nodeMounts[nodeName], startupPath)
			if len(dropped) != len(nodeMounts[nodeName]) {
				modified = true
			}
			nodeMounts[nodeName] = dropped

			// Prefer the skyforge-tuned images for stable SSH bootstrap.
			if strings.Contains(image, "/cisco_vios:15.9.3") && !strings.Contains(image, "-skyforge") {
				// Pin to a digest to avoid k8s/node tag caching (imagePullPolicy is typically IfNotPresent).
				cfg["image"] = "ghcr.io/forwardnetworks/vrnetlab/cisco_vios@sha256:6055038e6c024326a9630699d897a7a089b7af6925f5bcb7b162ba884dbe5f72"
				modified = true
			}
			if strings.Contains(image, "/cisco_viosl2:15.2") && !strings.Contains(image, "-skyforge") {
				// Pin to a digest to avoid k8s/node tag caching (imagePullPolicy is typically IfNotPresent).
				cfg["image"] = "ghcr.io/forwardnetworks/vrnetlab/cisco_viosl2@sha256:898301d2f9e609b7f008d5e419d0750f31a1ebf30afeb7e311592217b4ac620b"
				modified = true
			}

			// Minimal bootstrap-only config to ensure an SSH server exists for readiness.
			//
			// Keep this intentionally tiny and avoid interface configuration; netlab will
			// apply the full intended config post-boot via `netlab initial`.
			//
			// Use admin/admin bootstrap to match Skyforge credential defaults and avoid auth mismatches.
			user := "admin"
			pass := "admin"
			bootstrap := strings.TrimSpace(fmt.Sprintf(`
hostname %s
no ip domain lookup
ip domain name lab
username %s privilege 15 secret %s
ip ssh version 2
crypto key generate rsa modulus 2048
line vty 0 4
 login local
 transport input ssh
!
`, nodeName, user, pass))
			key := sanitizeArtifactKeySegment(fmt.Sprintf("%s-startup-config.cfg", nodeName))
			if key == "" || key == "unknown" {
				key = "startup-config.cfg"
			}
			overrideData[key] = bootstrap

			// Set startup-config path in topology for clarity (mount is handled by FilesFromConfigMap).
			cfg["startup-config"] = startupPath
			nodeMounts[nodeName] = upsertC9sMount(nodeMounts[nodeName], c9sFileFromConfigMap{
				ConfigMapName: overrideCM,
				ConfigMapPath: key,
				FilePath:      startupPath,
				Mode:          "read",
			})
			modified = true

			nodesAny[node] = cfg
			continue
		}

		// Some vrnetlab images handle their own bootstrap to enable SSH (IOSv/IOSvL2/IOL/IOLL2).
		// Mounting a full netlab-generated startup-config into /config/startup-config.cfg can slow or wedge
		// the bootstrap (e.g. interface config for NICs not yet attached, keygen prompts, etc) and prevent
		// SSH readiness. For these, rely on vrnetlab's native bootstrap and let `netlab initial` apply config
		// post-boot, matching the upstream netlab/containerlab workflow.
		if kind == "cisco_iol" || kind == "cisco_ioll2" || kind == "cisco_vios" || kind == "cisco_viosl2" {
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
		if !modified {
			return topologyYAML, nodeMounts, nil
		}
		topology["nodes"] = nodesAny
		topo["topology"] = topology
		out, err := yaml.Marshal(topo)
		if err != nil {
			return nil, nil, fmt.Errorf("encode clab.yml: %w", err)
		}
		return out, nodeMounts, nil
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

func applyVrnetlabNodeEnvOverrides(kind, image string, dpIntfs int, cfg map[string]any) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	image = strings.ToLower(strings.TrimSpace(image))
	if cfg == nil || kind == "" || image == "" {
		return
	}
	if !strings.Contains(image, "/vrnetlab/") {
		return
	}

	// vrnetlab discovers and attaches data-plane NICs by looking for container interfaces
	// (e.g. eth1, eth2, ...) *at QEMU start time*. In clabernetes the pod networking can
	// be created slightly after the container starts, so we must tell vrnetlab how many
	// data-plane interfaces to wait for, otherwise it can start QEMU too early and the
	// VM comes up missing interfaces (breaking netlab config application and SSH).
	if dpIntfs > 0 {
		upsertNodeEnvVar(cfg, "CLAB_INTFS", fmt.Sprintf("%d", dpIntfs))
	}

	// Many vrnetlab devices enable SSH by generating RSA keys on first boot. Without an entropy
	// source, key generation can take an extremely long time (or appear hung), which makes
	// SSH readiness unreliable. Attach a virtio RNG device backed by /dev/urandom.
	//
	// This is a QEMU-level tweak (not a NOS patch) and keeps behavior aligned with the
	// "device comes up and accepts SSH" expectation of containerlab/vrnetlab deployments.
	appendNodeEnvVarIfMissing(cfg, "QEMU_ADDITIONAL_ARGS",
		"-object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0",
		[]string{"virtio-rng", "rng-random"},
	)

	// Cisco ASAv often exposes boot output on the VGA console. Ensure it is redirected to
	// the serial console that vrnetlab monitors, otherwise the bootstrap never completes
	// and SSH is never enabled.
	//
	// Also bump QEMU memory/SMP to match our k8s resource requests for this kind.
	if kind == "cisco_asav" {
		appendNodeEnvVarIfMissing(cfg, "QEMU_ADDITIONAL_ARGS", "-nographic", []string{"-nographic"})
		upsertNodeEnvVar(cfg, "QEMU_MEMORY", 4096)
		upsertNodeEnvVar(cfg, "QEMU_SMP", 2)
	}
}

// countClabDataPlaneInterfaces estimates the number of data-plane interfaces for each node
// based on the containerlab topology links.
//
// This is used to set vrnetlab's CLAB_INTFS env var so it waits for eth1..ethN before
// launching QEMU, ensuring the VM sees all interfaces that netlab expects.
func countClabDataPlaneInterfaces(topology map[string]any) map[string]int {
	out := map[string]int{}
	if topology == nil {
		return out
	}
	linksAny, _ := topology["links"].([]any)
	for _, raw := range linksAny {
		switch v := raw.(type) {
		case string:
			// netlab's simplest link syntax: "r1-r2"
			parts := strings.Split(strings.TrimSpace(v), "-")
			if len(parts) != 2 {
				continue
			}
			a := strings.TrimSpace(parts[0])
			b := strings.TrimSpace(parts[1])
			if a != "" {
				out[a]++
			}
			if b != "" {
				out[b]++
			}
		case map[string]any:
			// containerlab-style link entries usually include `endpoints: [ "r1:eth1", "r2:eth1" ]`
			eps, _ := v["endpoints"].([]any)
			for _, epAny := range eps {
				ep := strings.TrimSpace(fmt.Sprintf("%v", epAny))
				if ep == "" {
					continue
				}
				node := strings.TrimSpace(strings.Split(ep, ":")[0])
				if node != "" {
					out[node]++
				}
			}
		default:
			continue
		}
	}
	return out
}

func upsertNodeEnvVar(cfg map[string]any, key string, value any) {
	key = strings.TrimSpace(key)
	if cfg == nil || key == "" {
		return
	}

	raw, ok := cfg["env"]
	if !ok || raw == nil {
		cfg["env"] = map[string]any{key: value}
		return
	}

	// netlab/containerlab uses a map for env vars; be conservative if the type is unexpected.
	envMap, ok := raw.(map[string]any)
	if !ok || envMap == nil {
		return
	}

	if _, exists := envMap[key]; !exists {
		envMap[key] = value
		cfg["env"] = envMap
	}
}

func appendNodeEnvVarIfMissing(cfg map[string]any, key string, suffix string, containsAny []string) {
	key = strings.TrimSpace(key)
	suffix = strings.TrimSpace(suffix)
	if cfg == nil || key == "" || suffix == "" {
		return
	}
	for _, needle := range containsAny {
		if strings.TrimSpace(needle) == "" {
			continue
		}
		if v, ok := cfg["env"].(map[string]any); ok && v != nil {
			if cur, ok := v[key]; ok {
				if s, ok := cur.(string); ok && strings.Contains(s, needle) {
					return
				}
			}
		}
	}

	raw, ok := cfg["env"]
	if !ok || raw == nil {
		cfg["env"] = map[string]any{key: suffix}
		return
	}
	envMap, ok := raw.(map[string]any)
	if !ok || envMap == nil {
		return
	}
	if curAny, ok := envMap[key]; ok {
		if cur, ok := curAny.(string); ok {
			cur = strings.TrimSpace(cur)
			if cur == "" {
				envMap[key] = suffix
			} else if !strings.Contains(cur, suffix) {
				envMap[key] = strings.TrimSpace(cur + " " + suffix)
			}
			cfg["env"] = envMap
			return
		}
		// If the current type isn't string, don't try to modify it.
		return
	}
	envMap[key] = suffix
	cfg["env"] = envMap
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

func dropC9sMountForPath(existing []c9sFileFromConfigMap, filePath string) []c9sFileFromConfigMap {
	filePath = strings.TrimSpace(filePath)
	if len(existing) == 0 || filePath == "" {
		return existing
	}
	out := existing[:0]
	for _, m := range existing {
		if strings.TrimSpace(m.FilePath) == filePath {
			continue
		}
		out = append(out, m)
	}
	return out
}
