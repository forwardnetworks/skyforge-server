package taskengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
		k8sNode  string
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
		k8sNode := strings.TrimSpace(podsNodeNameForTopologyNode(pods, topologyName, nodeName))
		work = append(work, workItem{
			nodeName: nodeName,
			kind:     kind,
			podName:  strings.TrimSpace(pinfo.podName),
			podIP:    strings.TrimSpace(pinfo.podIP),
			k8sNode:  k8sNode,
		})
	}

	if len(work) == 0 {
		return nil
	}

	log.Infof("c9s: post-up config starting: nodes=%d", len(work))

	// Cache per-Kubernetes-node gateway discovery.
	nodeGateway := map[string]string{}
	nodeGatewayMu := sync.Mutex{}

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
			gw := ""
			if item.k8sNode != "" {
				nodeGatewayMu.Lock()
				gw = strings.TrimSpace(nodeGateway[item.k8sNode])
				nodeGatewayMu.Unlock()
				if gw == "" {
					if discovered, ok := discoverNodeGateway(ctx, kcfg, ns, item.k8sNode, topologyName, pods); ok {
						gw = discovered
						nodeGatewayMu.Lock()
						nodeGateway[item.k8sNode] = gw
						nodeGatewayMu.Unlock()
					}
				}
			}
			if err := ensureNetlabC9sPodEth0(ctx, kcfg, ns, item.podName, item.podIP, gw, log); err != nil {
				log.Infof("c9s: eos eth0 restore failed for %s: %v", item.nodeName, err)
			}
		}()
	}
	wg.Wait()

	return nil
}

func podsNodeNameForTopologyNode(pods []kubePod, topologyName, topologyNode string) string {
	topologyName = strings.TrimSpace(topologyName)
	topologyNode = strings.TrimSpace(topologyNode)
	if topologyName == "" || topologyNode == "" || len(pods) == 0 {
		return ""
	}
	for _, p := range pods {
		if strings.TrimSpace(p.Metadata.Labels["clabernetes/topologyOwner"]) != topologyName {
			continue
		}
		if strings.TrimSpace(p.Metadata.Labels["clabernetes/topologyNode"]) != topologyNode {
			continue
		}
		return strings.TrimSpace(p.Spec.NodeName)
	}
	return ""
}

func discoverNodeGateway(ctx context.Context, kcfg *rest.Config, ns, k8sNode, topologyName string, pods []kubePod) (string, bool) {
	ns = strings.TrimSpace(ns)
	k8sNode = strings.TrimSpace(k8sNode)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || k8sNode == "" || topologyName == "" {
		return "", false
	}

	// Prefer the CiliumInternalIP for the node. This is the "router" / default gateway
	// for /32 pod addressing on that node.
	//
	// We need this fallback for topologies that don't include Linux nodes (for example
	// simple 2-node EOS OSPF labs). In those cases, cEOS may wipe the pod default route
	// in every pod, which makes it impossible to discover the gateway by exec'ing into
	// another pod on the node.
	if gw, ok := kubeGetCiliumInternalIP(ctx, k8sNode); ok {
		return gw, true
	}

	// Prefer Linux host nodes if present; those reliably retain the pod default route.
	candidates := make([]string, 0, 4)
	for _, p := range pods {
		if strings.TrimSpace(p.Spec.NodeName) != k8sNode {
			continue
		}
		if strings.TrimSpace(p.Metadata.Labels["clabernetes/topologyOwner"]) != topologyName {
			continue
		}
		topoNode := strings.TrimSpace(p.Metadata.Labels["clabernetes/topologyNode"])
		if topoNode == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(topoNode), "h") {
			candidates = append(candidates, strings.TrimSpace(p.Metadata.Name))
		}
	}
	// Fall back to any pod from this topology on the node.
	if len(candidates) == 0 {
		for _, p := range pods {
			if strings.TrimSpace(p.Spec.NodeName) != k8sNode {
				continue
			}
			if strings.TrimSpace(p.Metadata.Labels["clabernetes/topologyOwner"]) != topologyName {
				continue
			}
			if name := strings.TrimSpace(p.Metadata.Name); name != "" {
				candidates = append(candidates, name)
			}
		}
	}
	if len(candidates) == 0 {
		return "", false
	}

	script := `set -eu
gw="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
echo "${gw:-}"`

	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, podName := range candidates {
		if podName == "" {
			continue
		}
		stdout, _, err := kubeutil.ExecPodShell(ctxReq, kcfg, ns, podName, "clabernetes-launcher", script)
		if err != nil {
			continue
		}
		gw := strings.TrimSpace(stdout)
		if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
			return gw, true
		}
	}
	return "", false
}

type ciliumNode struct {
	Spec struct {
		Addresses []struct {
			Type string `json:"type"`
			IP   string `json:"ip"`
		} `json:"addresses"`
	} `json:"spec"`
}

func kubeGetCiliumInternalIP(ctx context.Context, nodeName string) (string, bool) {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return "", false
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return "", false
	}
	getURL := fmt.Sprintf("https://kubernetes.default.svc/apis/cilium.io/v2/ciliumnodes/%s", url.PathEscape(nodeName))
	req, err := kubeRequest(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	var cn ciliumNode
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cn); err != nil {
		return "", false
	}
	for _, a := range cn.Spec.Addresses {
		if strings.TrimSpace(a.Type) != "CiliumInternalIP" {
			continue
		}
		gw := strings.TrimSpace(a.IP)
		if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
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
ip route replace default via "$GW" dev "$dev" onlink
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
