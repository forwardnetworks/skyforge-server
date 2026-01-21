package taskengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
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
	type podNetInfo struct {
		podName string
		podIP   string
		gateway string
	}
	nodePod := map[string]podNetInfo{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			continue
		}
		info := podNetInfo{
			podName: strings.TrimSpace(pod.Metadata.Name),
			podIP:   strings.TrimSpace(pod.Status.PodIP),
		}
		if gw, ok := parseCNIStatusGateway(strings.TrimSpace(pod.Metadata.Annotations["k8s.v1.cni.cncf.io/network-status"])); ok {
			info.gateway = gw
		}
		nodePod[node] = info
	}

	kcfg, err := kubeutil.InClusterConfig()
	if err != nil {
		return err
	}

	type workItem struct {
		nodeName string
		kind     string
		podName  string
		podIP    string
		gateway  string
	}
	work := make([]workItem, 0)
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
		pinfo, ok := nodePod[nodeName]
		if !ok || strings.TrimSpace(pinfo.podName) == "" {
			log.Infof("c9s: post-up eos config skipped (pod not found): %s", nodeName)
			continue
		}
		work = append(work, workItem{
			nodeName: nodeName,
			kind:     kind,
			podName:  strings.TrimSpace(pinfo.podName),
			podIP:    strings.TrimSpace(pinfo.podIP),
			gateway:  strings.TrimSpace(pinfo.gateway),
		})
	}

	if len(work) == 0 {
		return nil
	}

	log.Infof("c9s: post-up config starting: nodes=%d", len(work))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var firstErr error
	var firstErrMu sync.Mutex

	for _, item := range work {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			configFiles := pickNetlabC9sEOSConfigSnippets(topologyName, item.nodeName, nodeMounts[item.nodeName])
			if len(configFiles) == 0 {
				log.Infof("c9s: post-up eos config skipped (no config snippet found): %s", item.nodeName)
			} else {
				if err := applyNetlabC9sEOSConfigSnippets(ctx, kcfg, ns, item.podName, item.nodeName, configFiles, log); err != nil {
					log.Infof("c9s: post-up eos config failed for %s: %v", item.nodeName, err)
					firstErrMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					firstErrMu.Unlock()
				} else {
					log.Infof("c9s: post-up eos config ok: node=%s files=%d elapsed=%s", item.nodeName, len(configFiles), time.Since(start).Truncate(100*time.Millisecond))
				}
			}

			// Ensure SSH is enabled (best-effort) so Forward can connect.
			if err := ensureNetlabC9sEOSSSH(ctx, kcfg, ns, item.podName, item.nodeName, log); err != nil {
				log.Infof("c9s: eos ssh enable failed for %s: %v", item.nodeName, err)
			}

			// Restore the Kubernetes/Cilium pod network on eth0 after cEOS has booted.
			// cEOS frequently wipes the pod IP and default route, which prevents the in-cluster
			// collector from reaching the device over SSH.
			if err := ensureNetlabC9sPodEth0(ctx, kcfg, ns, item.podName, item.podIP, item.gateway, log); err != nil {
				log.Infof("c9s: eos eth0 restore failed for %s: %v", item.nodeName, err)
			}
		}()
	}
	wg.Wait()

	return nil
}

type cniNetworkStatus struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface"`
	IPs       []string `json:"ips"`
	Gateway   []string `json:"gateway"`
	Default   bool     `json:"default"`
}

func parseCNIStatusGateway(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	var entries []cniNetworkStatus
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", false
	}
	for _, e := range entries {
		if strings.TrimSpace(e.Interface) != "eth0" && !e.Default {
			continue
		}
		if len(e.Gateway) == 0 {
			continue
		}
		gw := strings.TrimSpace(e.Gateway[0])
		if gw != "" {
			return gw, true
		}
	}
	return "", false
}

func ensureNetlabC9sPodEth0(ctx context.Context, kcfg *rest.Config, ns, podName, podIP, gateway string, log Logger) error {
	ns = strings.TrimSpace(ns)
	podName = strings.TrimSpace(podName)
	podIP = strings.TrimSpace(podIP)
	gateway = strings.TrimSpace(gateway)
	if ns == "" || podName == "" || podIP == "" || gateway == "" {
		return nil
	}

	script := fmt.Sprintf(`set -eu
IP=%q
GW=%q
dev=eth0
command -v ip >/dev/null 2>&1 || exit 0
ip link set dev "$dev" up || true

if ! ip -o -4 addr show dev "$dev" 2>/dev/null | grep -q "$IP/"; then
  ip addr flush dev "$dev" || true
  ip addr add "$IP/32" dev "$dev"
fi

# Cilium uses /32 addressing and a link-scoped route to the gateway.
ip route replace "$GW" dev "$dev" scope link
ip route replace default via "$GW" dev "$dev"
`, podIP, gateway)

	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Run in the launcher sidecar so we don't depend on NOS userland.
	_, _, err := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "clabernetes-launcher", script)
	if err == nil {
		return nil
	}
	// Fall back to whichever container is available.
	_, _, err2 := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "", script)
	if err2 == nil {
		return nil
	}
	if log != nil && err != nil {
		log.Infof("c9s: eth0 restore exec error: %v", err)
	}
	return err2
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
# Ensure SSH service is enabled.
timeout -k 2s 15s FastCli -p 15 -c "enable" -c "configure terminal" -c "management ssh" -c "no shutdown" -c "end" -c "write memory" >/dev/null 2>&1 || true
	echo "ssh enabled"
`, nodeName)

	// Best-effort; EOS can take a while to become CLI-ready.
	ctxReq, cancel := context.WithTimeout(ctx, 4*time.Minute)
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
	// Best-effort: if we timed out waiting for the CLI, don't fail the whole post-up.
	// We'll still have the startup-config injection and/or the next run.
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
			return nil
		}
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
  # Ensure SSH service is enabled.
  timeout -k 2s 15s FastCli -p 15 -c "enable" -c "configure terminal" -c "management ssh" -c "no shutdown" -c "end" -c "write memory" >/dev/null 2>&1 || true
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
