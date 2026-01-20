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
		configPath := pickNetlabC9sEOSConfigSnippet(topologyName, nodeName, nodeMounts[nodeName])
		if configPath == "" {
			log.Infof("c9s: post-up eos config skipped (no config snippet found): %s", nodeName)
			continue
		}

		if err := applyNetlabC9sEOSConfigSnippet(ctx, kcfg, ns, podName, nodeName, configPath, log); err != nil {
			// Best-effort: do not fail the run if a single node fails to apply cfglets.
			log.Infof("c9s: post-up eos config failed for %s: %v", nodeName, err)
		}
	}

	return nil
}

func pickNetlabC9sEOSConfigSnippet(topologyName, nodeName string, mounts []c9sFileFromConfigMap) string {
	topologyName = strings.TrimSpace(topologyName)
	nodeName = strings.TrimSpace(nodeName)
	if topologyName == "" || nodeName == "" || len(mounts) == 0 {
		return ""
	}
	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	nodeFilesRoot := path.Join(mountRoot, "node_files") + "/"

	type candidate struct {
		path  string
		score int
	}
	cands := []candidate{}

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

		// Only consider snippet-like files (exclude templates and inventory/state).
		base := strings.ToLower(path.Base(rel))
		switch {
		case base == "hosts.yml" || base == "hosts.yaml":
			continue
		case strings.HasSuffix(base, ".j2") || strings.HasSuffix(base, ".tmpl"):
			continue
		case strings.HasSuffix(base, ".py") || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
			continue
		case strings.Contains(strings.ToLower(rel), "/check.config/"):
			continue
		}

		// Common netlab pattern: `node_files/<node>/config` or `.../<node>.cfg`.
		score := 0
		if base == "config" {
			score = 100
		} else if base == strings.ToLower(nodeName)+".cfg" {
			score = 90
		} else if strings.HasSuffix(base, ".cfg") {
			score = 70
		} else if strings.HasSuffix(base, ".conf") {
			score = 60
		} else {
			continue
		}

		cands = append(cands, candidate{path: filePath, score: score})
	}

	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].path < cands[j].path
	})
	return cands[0].path
}

func applyNetlabC9sEOSConfigSnippet(ctx context.Context, kcfg *rest.Config, ns, podName, nodeName, filePath string, log Logger) error {
	ns = strings.TrimSpace(ns)
	podName = strings.TrimSpace(podName)
	nodeName = strings.TrimSpace(nodeName)
	filePath = strings.TrimSpace(filePath)
	if ns == "" || podName == "" || nodeName == "" || filePath == "" {
		return nil
	}

	// Some file mounts are materialized as directories containing the configmap key as the file.
	// Try both the direct file path and a "filePath/configMapPath" fallback (common pattern when
	// clabernetes mounts configmap keys under a directory).
	// Conservative: the fallback filename isn't known here. We'll probe a few common ones in-shell.

	script := fmt.Sprintf(`set -eu
NODE=%q
FP=%q
command -v Cli >/dev/null 2>&1 || { echo "Cli not found; skipping"; exit 0; }
try_file() {
  f="$1"
  [ -f "$f" ] || return 1
  # Wait for EOS CLI readiness.
  i=0
  while [ $i -lt 120 ]; do
    Cli -p 15 -c "show version" >/dev/null 2>&1 && break
    sleep 1
    i=$((i+1))
  done
  # Apply lines (best-effort). Skip comments and "end".
  while IFS= read -r line; do
    line="${line%%$'\r'}"
    case "$line" in
      ""|"!"*|"#"*|"end") continue ;;
    esac
    Cli -p 15 -c "enable" -c "configure terminal" -c "$line" >/dev/null 2>&1 || true
  done < "$f"
  Cli -p 15 -c "write memory" >/dev/null 2>&1 || true
  echo "applied config snippet: $f"
  return 0
}

if try_file "$FP"; then
  exit 0
fi

# Fallback probes: treat FP as a directory.
try_file "$FP/config" && exit 0 || true
try_file "$FP/config.cfg" && exit 0 || true
try_file "$FP/%s.cfg" && exit 0 || true
try_file "$FP/%s.conf" && exit 0 || true

echo "no config snippet found at $FP (or common fallbacks)"
exit 0
`, nodeName, filePath, nodeName, nodeName)

	ctxReq, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	stdout, stderr, err := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "nos", script)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "container") {
		// Retry without explicit container (single-container pods).
		stdout2, stderr2, err2 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "", script)
		if err2 == nil {
			stdout, stderr, err = stdout2, stderr2, nil
		} else {
			err = err2
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
