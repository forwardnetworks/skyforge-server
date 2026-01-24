package taskengine

import (
	"context"
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// injectNetlabC9sIOSXEServerVRF patches vrnetlab IOS/IOS-XE netlab "initial" config
// snippets to ensure the SSH server listens in the management VRF when the management
// interface is placed in that VRF (common for vrnetlab Cisco IOL/IOS-XE images).
//
// This is a config injection (not link plumbing): it does not touch interface wiring
// or any clabernetes connectivity.
func injectNetlabC9sIOSXEServerVRF(
	ctx context.Context,
	ns string,
	topologyName string,
	clabYAML []byte,
	nodeMounts map[string][]c9sFileFromConfigMap,
	log Logger,
) ([]byte, map[string][]c9sFileFromConfigMap, error) {
	if log == nil {
		log = noopLogger{}
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" || len(clabYAML) == 0 || nodeMounts == nil {
		return clabYAML, nodeMounts, nil
	}

	// Identify IOS/IOS-XE vrnetlab nodes from the generated containerlab YAML.
	nodesByKind, err := clabNodesByKind(clabYAML)
	if err != nil {
		return nil, nil, err
	}
	if len(nodesByKind) == 0 {
		return clabYAML, nodeMounts, nil
	}

	// Only Cisco IOS-like vrnetlab kinds use this mgmt-VRF pattern today.
	iosKinds := map[string]bool{
		"cisco_iol":  true, // IOS-XE from Forward's perspective
		"cisco_vios": true,
		"cisco_viosl2": true,
	}

	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}

	changedAny := false
	changedFiles := 0

	for nodeName, kind := range nodesByKind {
		if !iosKinds[strings.ToLower(strings.TrimSpace(kind))] {
			continue
		}
		mounts := nodeMounts[nodeName]
		if len(mounts) == 0 {
			continue
		}

		// netlab generator exposes per-node config snippets as node_files/<node>/<rel>.
		// For vrnetlab IOS/IOS-XE we need to tweak the "initial" snippet, which is later
		// merged into /vrnetlab/config.txt by the launcher/init sequence.
		var cfgMountIdx int = -1
		var originalCM, originalKey string
		for i, m := range mounts {
			if strings.TrimSpace(m.ConfigMapName) == "" {
				continue
			}
			if strings.EqualFold(path.Base(strings.TrimSpace(m.FilePath)), "initial") {
				cfgMountIdx = i
				originalCM = strings.TrimSpace(m.ConfigMapName)
				originalKey = strings.TrimSpace(m.ConfigMapPath)
				break
			}
		}
		if cfgMountIdx < 0 || originalCM == "" || originalKey == "" {
			continue
		}

		cmData, ok, err := kubeGetConfigMap(ctx, ns, originalCM)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		contents, ok := cmData[originalKey]
		if !ok {
			continue
		}

		out, changed := injectIOSXESSHServerVRF(contents, "clab-mgmt", "Ethernet0/0")
		if !changed {
			continue
		}

		// Create a per-node override ConfigMap with the SAME key name ("initial") so clabernetes'
		// native-mode Cisco IOL helper can still mount /netlab/initial.cfg by matching ConfigMapPath == "initial".
		//
		// Using per-node ConfigMaps avoids key collisions while preserving the expected key name.
		overrideCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-%s-iosxe-initial", topologyName, nodeName), "c9s-iosxe-initial")
		overrideData := map[string]string{
			"initial": out,
		}
		if err := kubeUpsertConfigMap(ctx, ns, overrideCM, overrideData, labels); err != nil {
			return nil, nil, err
		}

		// Update the mount that corresponds to config.txt.
		mounts[cfgMountIdx].ConfigMapName = overrideCM
		mounts[cfgMountIdx].ConfigMapPath = "initial"
		changedAny = true
		changedFiles++
		nodeMounts[nodeName] = mounts
	}

	if !changedAny {
		return clabYAML, nodeMounts, nil
	}
	log.Infof("c9s: injected iosxe ssh server vrf into netlab initial config (%d file(s))", changedFiles)
	return clabYAML, nodeMounts, nil
}

func clabNodesByKind(clabYAML []byte) (map[string]string, error) {
	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return nil, fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	topology, ok := topo["topology"].(map[string]any)
	if !ok || topology == nil {
		return nil, nil
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || len(nodes) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for node, nodeAny := range nodes {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"]))
		out[nodeName] = kind
	}
	return out, nil
}

func injectIOSXESSHServerVRF(cfg string, vrfName string, srcIntf string) (out string, changed bool) {
	cfg = strings.ReplaceAll(cfg, "\r\n", "\n")
	vrfName = strings.TrimSpace(vrfName)
	srcIntf = strings.TrimSpace(srcIntf)

	lower := strings.ToLower(cfg)
	needServerVRF := vrfName != "" && !strings.Contains(lower, "\nip ssh server vrf "+strings.ToLower(vrfName))
	needSource := srcIntf != "" && !strings.Contains(lower, "\nip ssh source-interface "+strings.ToLower(srcIntf))
	if !needServerVRF && !needSource {
		return cfg, false
	}

	linesToInsert := make([]string, 0, 2)
	if needServerVRF {
		linesToInsert = append(linesToInsert, "ip ssh server vrf "+vrfName)
	}
	if needSource {
		// For IOS/IOS-XE, this influences the source interface for outbound SSH;
		// it is harmless here and can help ensure the mgmt VRF path is used consistently.
		linesToInsert = append(linesToInsert, "ip ssh source-interface "+srcIntf)
	}

	lines := strings.Split(cfg, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(strings.ToLower(lines[i])) == "end" {
			outLines := make([]string, 0, len(lines)+len(linesToInsert))
			outLines = append(outLines, lines[:i]...)
			outLines = append(outLines, linesToInsert...)
			outLines = append(outLines, lines[i:]...)
			out = strings.Join(outLines, "\n")
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			return out, true
		}
	}
	if !strings.HasSuffix(cfg, "\n") {
		cfg += "\n"
	}
	return cfg + strings.Join(linesToInsert, "\n") + "\n", true
}
