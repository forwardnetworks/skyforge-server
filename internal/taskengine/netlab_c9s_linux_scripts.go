package taskengine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"encore.app/internal/kubeutil"
	"gopkg.in/yaml.v3"
)

type netlabC9sLinuxScriptResult struct {
	Node   string
	Script string
	Stdout string
	Stderr string
	Err    error
}

func prepareNetlabC9sLinuxInterfaces(ctx context.Context, ns, podName, container string) (stdout, stderr string, err error) {
	cmd := `set -e
if ! command -v ip >/dev/null 2>&1; then
  echo "ip command not found; skipping interface prep"
  exit 0
fi

# Multus typically attaches secondary interfaces as net1, net2, ...
# Netlab-generated scripts expect eth1, eth2, ...
for i in $(seq 1 32); do
  if ip link show dev "eth${i}" >/dev/null 2>&1; then
    continue
  fi
  if ip link show dev "net${i}" >/dev/null 2>&1; then
    ip link set dev "net${i}" down >/dev/null 2>&1 || true
    ip link set dev "net${i}" name "eth${i}" >/dev/null 2>&1 || true
  fi
done
`
	kcfg, err := kubeutil.InClusterConfig()
	if err != nil {
		return "", "", err
	}
	return kubeutil.ExecPodShell(ctx, kcfg, ns, podName, container, cmd)
}

func runNetlabC9sLinuxScripts(ctx context.Context, ns, topologyOwner string, topologyYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, enableSSH bool, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	ns = strings.TrimSpace(ns)
	topologyOwner = strings.TrimSpace(topologyOwner)
	if ns == "" || topologyOwner == "" {
		return fmt.Errorf("namespace and topology owner are required")
	}
	if len(topologyYAML) == 0 {
		return fmt.Errorf("topology yaml is empty")
	}

	var topo map[string]any
	if err := yaml.Unmarshal(topologyYAML, &topo); err != nil {
		return fmt.Errorf("failed to parse topology yaml: %w", err)
	}
	topology, _ := topo["topology"].(map[string]any)
	nodesAny, _ := topology["nodes"].(map[string]any)
	if len(nodesAny) == 0 {
		return nil
	}

	linuxNodes := make([]string, 0)
	for node, nodeAny := range nodesAny {
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind != "linux" {
			continue
		}
		linuxNodes = append(linuxNodes, strings.TrimSpace(node))
	}
	if len(linuxNodes) == 0 {
		return nil
	}

	// Map topologyNode -> pod name.
	pods, err := kubeListPods(ctx, ns, map[string]string{"clabernetes/topologyOwner": topologyOwner})
	if err != nil {
		return err
	}
	podByNode := map[string]string{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		name := strings.TrimSpace(pod.Metadata.Name)
		if node == "" || name == "" {
			continue
		}
		podByNode[node] = name
	}

	kcfg, err := kubeutil.InClusterConfig()
	if err != nil {
		return err
	}

	scripts := []string{"initial", "routing"}

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	// We buffer all results because we only drain the channel after all goroutines
	// complete. Make sure the capacity accounts for every goroutine that writes a
	// result, otherwise we'll deadlock on send.
	//
	// Per node:
	// - 1x prep-interfaces
	// - len(scripts) script runs
	// - optional 1x ssh enable
	capacity := len(linuxNodes) * (1 + len(scripts))
	if enableSSH {
		capacity += len(linuxNodes)
	}
	results := make(chan netlabC9sLinuxScriptResult, capacity)

	for _, node := range linuxNodes {
		node := strings.TrimSpace(node)
		podName := strings.TrimSpace(podByNode[node])
		if podName == "" {
			podName = strings.TrimSpace(podByNode[strings.ToLower(node)])
		}
		container := strings.ToLower(strings.TrimSpace(node))
		if node == "" || podName == "" {
			continue
		}

		// Prepare interface names for netlab scripts (best-effort).
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctxExec, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			stdout, stderr, err := prepareNetlabC9sLinuxInterfaces(ctxExec, ns, podName, container)
			results <- netlabC9sLinuxScriptResult{
				Node:   node,
				Script: "prep-interfaces",
				Stdout: strings.TrimSpace(stdout),
				Stderr: strings.TrimSpace(stderr),
				Err:    err,
			}
		}()

		for _, script := range scripts {
			script := script
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Run from the netlab-generated configmap, not from a mounted file:
				// clabernetes mounts filesFromConfigMap into the launcher sidecar, not into the linux node container.
				cmName := ""
				if nodeMounts != nil {
					if mounts, ok := nodeMounts[container]; ok {
						for _, m := range mounts {
							if strings.TrimSpace(m.ConfigMapName) != "" {
								cmName = strings.TrimSpace(m.ConfigMapName)
								break
							}
						}
					}
				}
				if cmName == "" {
					results <- netlabC9sLinuxScriptResult{Node: node, Script: script}
					return
				}
				data, ok, err := kubeGetConfigMap(ctx, ns, cmName)
				if err != nil || !ok {
					if err == nil && !ok {
						err = fmt.Errorf("configmap not found: %s", cmName)
					}
					results <- netlabC9sLinuxScriptResult{Node: node, Script: script, Err: err}
					return
				}
				body := strings.TrimSpace(data[script])
				if body == "" {
					results <- netlabC9sLinuxScriptResult{Node: node, Script: script}
					return
				}
				cmd := fmt.Sprintf("set -e\ncat > /tmp/skyforge-netlab-%s.sh <<'EOF_SKYFORGE'\n%s\nEOF_SKYFORGE\nchmod +x /tmp/skyforge-netlab-%s.sh 2>/dev/null || true\nsh /tmp/skyforge-netlab-%s.sh\n", script, body, script, script)
				ctxExec, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				stdout, stderr, err := kubeutil.ExecPodShell(ctxExec, kcfg, ns, podName, container, cmd)
				results <- netlabC9sLinuxScriptResult{
					Node:   node,
					Script: script,
					Stdout: strings.TrimSpace(stdout),
					Stderr: strings.TrimSpace(stderr),
					Err:    err,
				}
			}()
		}

		if enableSSH {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				cmd := `set -e
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache openssh-server >/dev/null 2>&1 || true
fi
mkdir -p /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
if [ -f /etc/ssh/sshd_config ]; then
  grep -q '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
  grep -q '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
fi
/usr/sbin/sshd -D -e >/dev/null 2>&1 &`

				ctxExec, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				stdout, stderr, err := kubeutil.ExecPodShell(ctxExec, kcfg, ns, podName, container, cmd)
				results <- netlabC9sLinuxScriptResult{
					Node:   node,
					Script: "ssh",
					Stdout: strings.TrimSpace(stdout),
					Stderr: strings.TrimSpace(stderr),
					Err:    err,
				}
			}()
		}
	}

	wg.Wait()
	close(results)

	// Linux hosts are nice-to-have. We log failures but do not fail the overall run.
	for res := range results {
		if res.Err != nil {
			log.Errorf("netlab linux script failed node=%s script=%s err=%v stderr=%s", res.Node, res.Script, res.Err, res.Stderr)
			continue
		}
		if res.Stdout != "" {
			log.Infof("netlab linux script node=%s script=%s: %s", res.Node, res.Script, res.Stdout)
		} else {
			log.Infof("netlab linux script node=%s script=%s: ok", res.Node, res.Script)
		}
		if res.Stderr != "" {
			log.Infof("netlab linux script node=%s script=%s stderr: %s", res.Node, res.Script, res.Stderr)
		}
	}
	return nil
}
