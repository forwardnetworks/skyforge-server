package taskengine

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"encore.app/internal/kubeutil"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/rest"
)

func runNetlabC9sNOSPostUp(ctx context.Context, ns, topologyName string, topologyYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" || len(topologyYAML) == 0 || len(nodeMounts) == 0 {
		return nil
	}

	var topo map[string]any
	if err := yaml.Unmarshal(topologyYAML, &topo); err != nil {
		return fmt.Errorf("parse clab.yml: %w", err)
	}
	topology, ok := topo["topology"].(map[string]any)
	if !ok {
		return nil
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || len(nodes) == 0 {
		return nil
	}

	pods, err := kubeListPods(ctx, ns, map[string]string{
		"clabernetes/topologyOwner": topologyName,
	})
	if err != nil {
		return err
	}
	nodePodName := map[string]string{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			continue
		}
		nodePodName[node] = strings.TrimSpace(pod.Metadata.Name)
	}

	kcfg, err := kubeutil.InClusterConfig()
	if err != nil {
		return err
	}

	// Apply post-up config for supported NOS kinds (start with EOS/cEOS).
	for node, nodeAny := range nodes {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind != "eos" && kind != "ceos" {
			continue
		}
		podName := strings.TrimSpace(nodePodName[nodeName])
		if podName == "" {
			log.Infof("c9s: post-up eos config skipped (pod not found): %s", nodeName)
			continue
		}
		configFiles := pickNetlabC9sEOSConfigSnippets(topologyName, nodeName, nodeMounts[nodeName])
		if len(configFiles) == 0 {
			log.Infof("c9s: post-up eos config skipped (no config snippet found): %s", nodeName)
			// Still try to enable SSH so Forward can connect even if we have no cfglets.
			if err := ensureNetlabC9sEOSSSH(ctx, kcfg, ns, podName, nodeName, log); err != nil {
				log.Infof("c9s: eos ssh enable failed for %s: %v", nodeName, err)
			}
			continue
		}

		if err := applyNetlabC9sEOSConfigSnippets(ctx, kcfg, ns, podName, nodeName, configFiles, log); err != nil {
			// Best-effort: do not fail the run if a single node fails to apply cfglets.
			log.Infof("c9s: post-up eos config failed for %s: %v", nodeName, err)
		}
	}

	return nil
}

func pickNetlabC9sEOSConfigSnippets(topologyName, nodeName string, mounts []c9sFileFromConfigMap) []string {
	topologyName = strings.TrimSpace(topologyName)
	nodeName = strings.TrimSpace(nodeName)
	if topologyName == "" || nodeName == "" || len(mounts) == 0 {
		return nil
	}
	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	nodeFilesRoot := path.Join(mountRoot, "node_files") + "/"

	// Netlab writes one snippet per module phase into node_files/<node>/<phase>.
	// Apply in a stable, opinionated order (remaining snippets appended).
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
	byBase := map[string]string{}
	extras := []string{}

	for _, m := range mounts {
		filePath := strings.TrimSpace(m.FilePath)
		if !strings.HasPrefix(filePath, nodeFilesRoot) {
			continue
		}
		relWithNode := strings.TrimPrefix(filePath, nodeFilesRoot)
		relWithNode = strings.TrimPrefix(relWithNode, "/")
		if relWithNode == "" || strings.HasPrefix(relWithNode, "..") {
			continue
		}
		parts := strings.SplitN(relWithNode, "/", 2)
		if len(parts) != 2 {
			continue
		}
		// Netlab may preserve node names as-is while clabernetes sanitizes them.
		// Match node directory case-insensitively and accept either variant.
		if !strings.EqualFold(strings.TrimSpace(parts[0]), nodeName) {
			continue
		}

		rel := parts[1]
		rel = strings.TrimPrefix(rel, "/")
		rel = path.Clean(rel)
		if rel == "." || rel == "" || strings.HasPrefix(rel, "..") {
			continue
		}

		base := strings.ToLower(path.Base(rel))
		// Exclude templates and inventory/state.
		if base == "hosts.yml" || base == "hosts.yaml" {
			continue
		}
		if strings.HasSuffix(base, ".j2") || strings.HasSuffix(base, ".tmpl") {
			continue
		}
		if strings.HasSuffix(base, ".py") || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") {
			continue
		}
		if strings.Contains(strings.ToLower(rel), "/check.config/") {
			continue
		}

		byBase[base] = filePath
	}

	seen := map[string]bool{}
	out := []string{}
	for _, base := range knownOrder {
		fp := strings.TrimSpace(byBase[strings.ToLower(base)])
		if fp == "" {
			continue
		}
		out = append(out, fp)
		seen[fp] = true
	}
	for _, fp := range byBase {
		fp = strings.TrimSpace(fp)
		if fp == "" || seen[fp] {
			continue
		}
		extras = append(extras, fp)
	}
	sort.Strings(extras)
	out = append(out, extras...)
	return out
}

func ensureNetlabC9sEOSSSH(ctx context.Context, kcfg *rest.Config, ns, podName, nodeName string, log Logger) error {
	ns = strings.TrimSpace(ns)
	podName = strings.TrimSpace(podName)
	nodeName = strings.TrimSpace(nodeName)
	if ns == "" || podName == "" || nodeName == "" {
		return nil
	}
	script := fmt.Sprintf(`set -eu
NODE=%q
command -v FastCli >/dev/null 2>&1 || { echo "FastCli not found; skipping"; exit 0; }
command -v timeout >/dev/null 2>&1 || { echo "timeout not found; skipping"; exit 0; }
i=0
while [ $i -lt 180 ]; do
  timeout -k 2s 5s FastCli -p 15 -c "show version" >/dev/null 2>&1 && break
  sleep 1
  i=$((i+1))
done
timeout -k 2s 10s FastCli -p 15 -c "enable" -c "configure terminal" -c "management ssh" -c "end" -c "write memory" >/dev/null 2>&1 || true
	echo "ssh enabled"
`, nodeName)

	ctxReq, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	// Native clabernetes uses a multi-container pod:
	// - node container (named after the node, e.g. "l3")
	// - clabernetes-launcher sidecar
	// - clabernetes-setup init container
	// Exec must target the node container.
	stdout, stderr, err := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, nodeName, script)
	if err != nil {
		stdout2, stderr2, err2 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, strings.ToLower(nodeName), script)
		if err2 == nil {
			stdout, stderr, err = stdout2, stderr2, nil
		} else {
			stdout3, stderr3, err3 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "nos", script)
			if err3 == nil {
				stdout, stderr, err = stdout3, stderr3, nil
			} else {
				stdout4, stderr4, err4 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "", script)
				if err4 == nil {
					stdout, stderr, err = stdout4, stderr4, nil
				}
			}
		}
	}
	if strings.TrimSpace(stdout) != "" {
		log.Infof("c9s: eos ssh %s stdout:\n%s", nodeName, strings.TrimSpace(stdout))
	}
	if strings.TrimSpace(stderr) != "" {
		log.Infof("c9s: eos ssh %s stderr:\n%s", nodeName, strings.TrimSpace(stderr))
	}
	return err
}

func applyNetlabC9sEOSConfigSnippets(ctx context.Context, kcfg *rest.Config, ns, podName, nodeName string, files []string, log Logger) error {
	ns = strings.TrimSpace(ns)
	podName = strings.TrimSpace(podName)
	nodeName = strings.TrimSpace(nodeName)
	if ns == "" || podName == "" || nodeName == "" || len(files) == 0 {
		return nil
	}

	cleanFiles := []string{}
	for _, fp := range files {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		cleanFiles = append(cleanFiles, fp)
	}
	if len(cleanFiles) == 0 {
		return nil
	}

	// Apply module snippets in order. Also ensures SSH is enabled (needed for Forward reachability).
	fileList := strings.Join(cleanFiles, "\n")

	script := fmt.Sprintf(`set -eu
NODE=%q
command -v FastCli >/dev/null 2>&1 || { echo "FastCli not found; skipping"; exit 0; }
command -v timeout >/dev/null 2>&1 || { echo "timeout not found; skipping"; exit 0; }
try_file() {
  f="$1"
  [ -f "$f" ] || return 1
  # Wait for EOS readiness.
  i=0
  while [ $i -lt 180 ]; do
    timeout -k 2s 5s FastCli -p 15 -c "show version" >/dev/null 2>&1 && break
    sleep 1
    i=$((i+1))
  done
  # Ensure SSH is enabled.
  timeout -k 2s 10s FastCli -p 15 -c "enable" -c "configure terminal" -c "management ssh" -c "end" -c "write memory" >/dev/null 2>&1 || true
  # Apply lines (best-effort). Skip comments and "end".
  while IFS= read -r line; do
    line="${line%%$'\r'}"
    case "$line" in
      ""|"!"*|"#"*|"end") continue ;;
    esac
    timeout -k 2s 10s FastCli -p 15 -c "enable" -c "configure terminal" -c "$line" >/dev/null 2>&1 || true
  done < "$f"
  timeout -k 2s 10s FastCli -p 15 -c "write memory" >/dev/null 2>&1 || true
  echo "applied config snippet: $f"
  return 0
}

while IFS= read -r fp; do
  [ -n "$fp" ] || continue
  try_file "$fp" || true
done <<'EOF_SKYFORGE_FILES'
%s
EOF_SKYFORGE_FILES
	exit 0
`, nodeName, fileList)

	ctxReq, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	stdout, stderr, err := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, nodeName, script)
	if err != nil {
		stdout2, stderr2, err2 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, strings.ToLower(nodeName), script)
		if err2 == nil {
			stdout, stderr, err = stdout2, stderr2, nil
		} else {
			stdout3, stderr3, err3 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "nos", script)
			if err3 == nil {
				stdout, stderr, err = stdout3, stderr3, nil
			} else {
				stdout4, stderr4, err4 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "", script)
				if err4 == nil {
					stdout, stderr, err = stdout4, stderr4, nil
				}
			}
		}
	}
	if strings.TrimSpace(stdout) != "" {
		log.Infof("c9s: eos post-up %s stdout:\n%s", nodeName, strings.TrimSpace(stdout))
	}
	if strings.TrimSpace(stderr) != "" {
		log.Infof("c9s: eos post-up %s stderr:\n%s", nodeName, strings.TrimSpace(stderr))
	}
	return err
}
