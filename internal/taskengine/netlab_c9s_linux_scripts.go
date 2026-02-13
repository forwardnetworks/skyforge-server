package taskengine

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
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

func runNetlabC9sLinuxScripts(ctx context.Context, ns, topologyOwner string, topologyYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, enableSSH bool, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	enableNoise := envBoolValue(os.Getenv("SKYFORGE_NETLAB_C9S_LINUX_NOISE"), true)
	noiseIntervalSeconds := 10
	if raw := strings.TrimSpace(os.Getenv("SKYFORGE_NETLAB_C9S_LINUX_NOISE_INTERVAL_SECONDS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 3600 {
			noiseIntervalSeconds = n
		}
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
	linuxScriptsByNode := map[string][]string{}
	for node, nodeAny := range nodesAny {
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind != "linux" {
			continue
		}
		nodeName := strings.TrimSpace(node)
		if nodeName == "" {
			continue
		}
		linuxNodes = append(linuxNodes, nodeName)

		// Netlab 26.02 native mode for linux devices uses script execution (provider-side
		// docker exec). In Kubernetes-native mode we execute the same per-node script
		// modules via pod exec; discover module order from bind mounts.
		scripts := linuxScriptModulesFromBinds(cfg)
		if len(scripts) == 0 {
			// Backward-compatible fallback for older generated topologies.
			scripts = []string{"initial", "routing"}
		}
		linuxScriptsByNode[nodeName] = scripts
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

	concurrency := 6
	if raw := strings.TrimSpace(os.Getenv("SKYFORGE_NETLAB_C9S_LINUX_CONCURRENCY")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 64 {
			concurrency = n
		}
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	// We buffer all results because we only drain the channel after all goroutines complete.
	capacity := 0
	for _, node := range linuxNodes {
		perNode := 1 + len(linuxScriptsByNode[node]) // prep + script modules
		if enableSSH {
			perNode++
		}
		if enableNoise {
			perNode++
		}
		capacity += perNode
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
		scripts := linuxScriptsByNode[node]
		if len(scripts) == 0 {
			scripts = []string{"initial", "routing"}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Run all per-node steps in a single exec to reduce k0s/konnectivity flakiness and
			// speed up deployments (fewer round-trips through the apiserver exec proxy).
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

			data := map[string]string{}
			if cmName != "" {
				m, ok, err := kubeGetConfigMap(ctx, ns, cmName)
				if err != nil {
					// Keep going; we still run prep/ssh/noise and mark module scripts as no-op.
					log.Errorf("netlab linux script failed node=%s script=configmap err=%v stderr=", node, err)
				} else if ok {
					data = m
				}
			}

			step := func(name, body string) string {
				body = strings.TrimSpace(body)
				if body == "" {
					return fmt.Sprintf("echo \"__SKYFORGE_STEP_BEGIN__ %s\"; echo \"__SKYFORGE_STEP_END__ %s 0\";\n", name, name)
				}
				tmp := fmt.Sprintf("/tmp/skyforge-netlab-%s.sh", name)
				return fmt.Sprintf(
					"echo \"__SKYFORGE_STEP_BEGIN__ %s\";\n( set -e; cat > %s <<'EOF_SKYFORGE'\n%s\nEOF_SKYFORGE\nchmod +x %s 2>/dev/null || true\nsh %s\n); rc=$?; echo \"__SKYFORGE_STEP_END__ %s ${rc}\";\n",
					name, tmp, body, tmp, tmp, name,
				)
			}

			// Interface prep (best-effort).
			prep := `echo "__SKYFORGE_STEP_BEGIN__ prep-interfaces"
( set -e
  if ! command -v ip >/dev/null 2>&1; then
    echo "ip command not found; skipping interface prep"
    exit 0
  fi
  for i in $(seq 1 32); do
    if ip link show dev "eth${i}" >/dev/null 2>&1; then
      continue
    fi
    if ip link show dev "net${i}" >/dev/null 2>&1; then
      ip link set dev "net${i}" down >/dev/null 2>&1 || true
      ip link set dev "net${i}" name "eth${i}" >/dev/null 2>&1 || true
    fi
  done
); rc=$?; echo "__SKYFORGE_STEP_END__ prep-interfaces ${rc}"
`

			sshEnable := ""
			if enableSSH {
				sshEnable = `echo "__SKYFORGE_STEP_BEGIN__ ssh"
( set -e
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache openssh-server >/dev/null 2>&1 || true
  fi
  mkdir -p /var/run/sshd
  ssh-keygen -A >/dev/null 2>&1 || true
  if command -v chpasswd >/dev/null 2>&1; then
    echo "root:admin" | chpasswd >/dev/null 2>&1 || true
  fi
  if command -v passwd >/dev/null 2>&1; then
    ( echo admin; echo admin ) | passwd root >/dev/null 2>&1 || true
  fi
  if [ -f /etc/ssh/sshd_config ]; then
    grep -q '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
    grep -q '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
  fi
  /usr/sbin/sshd -D -e >/dev/null 2>&1 &
); rc=$?; echo "__SKYFORGE_STEP_END__ ssh ${rc}"
`
			}

			noise := ""
			if enableNoise {
				noise = `echo "__SKYFORGE_STEP_BEGIN__ noise"
( set -e
  if [ -f /tmp/skyforge-noise.pid ] && kill -0 "$(cat /tmp/skyforge-noise.pid 2>/dev/null)" 2>/dev/null; then
    echo "noise already running"
    exit 0
  fi
  nohup sh -c '
  while true; do
    if command -v ip >/dev/null 2>&1; then
      for ifname in $(ip -o link show | awk -F": " "{print $2}" | grep -E "^eth[1-9][0-9]*$" || true); do
        ip4=$(ip -4 -o addr show dev "$ifname" 2>/dev/null | awk "{print $4}" | head -n1)
        ip4=${ip4%%/*}
        if [ -n "$ip4" ] && command -v arping >/dev/null 2>&1; then
          arping -U -c 1 -I "$ifname" "$ip4" >/dev/null 2>&1 || true
        fi
      done
      gw=$(ip route show default 2>/dev/null | awk "{print $3}" | head -n1)
      if [ -n "$gw" ] && command -v ping >/dev/null 2>&1; then
        ping -c 1 -W 1 "$gw" >/dev/null 2>&1 || true
      fi
    fi
    sleep ` + strconv.Itoa(noiseIntervalSeconds) + `
  done
  ' >/dev/null 2>&1 &
  echo $! > /tmp/skyforge-noise.pid
  echo "noise started (interval=` + strconv.Itoa(noiseIntervalSeconds) + `s)"
); rc=$?; echo "__SKYFORGE_STEP_END__ noise ${rc}"
`
			}

			combined := strings.Builder{}
			combined.WriteString("set +e\n")
			combined.WriteString(prep)
			for _, s := range scripts {
				combined.WriteString(step(s, data[s]))
			}
			if sshEnable != "" {
				combined.WriteString(sshEnable)
			}
			if noise != "" {
				combined.WriteString(noise)
			}
			combined.WriteString("\nexit 0\n")

			ctxExec, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			stdout, stderr, err := kubeutil.ExecPodShell(ctxExec, kcfg, ns, podName, container, combined.String())
			stdout = strings.TrimSpace(stdout)
			stderr = strings.TrimSpace(stderr)
			if err != nil {
				// We couldn't exec at all; emit a failure for each step so downstream logs are consistent.
				for _, s := range append(append([]string{"prep-interfaces"}, scripts...), func() []string {
					extra := []string{}
					if enableSSH {
						extra = append(extra, "ssh")
					}
					if enableNoise {
						extra = append(extra, "noise")
					}
					return extra
				}()...) {
					results <- netlabC9sLinuxScriptResult{
						Node:   node,
						Script: s,
						Stdout: "",
						Stderr: stderr,
						Err:    err,
					}
				}
				return
			}

			// Parse step markers so we keep per-script log lines without multiple execs.
			type stepRes struct {
				lines []string
				rc    int
			}
			steps := map[string]*stepRes{}
			var current string
			for _, line := range strings.Split(stdout, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "__SKYFORGE_STEP_BEGIN__ ") {
					current = strings.TrimSpace(strings.TrimPrefix(line, "__SKYFORGE_STEP_BEGIN__ "))
					if current != "" && steps[current] == nil {
						steps[current] = &stepRes{lines: []string{}, rc: 0}
					}
					continue
				}
				if strings.HasPrefix(line, "__SKYFORGE_STEP_END__ ") {
					rest := strings.TrimSpace(strings.TrimPrefix(line, "__SKYFORGE_STEP_END__ "))
					parts := strings.Fields(rest)
					if len(parts) >= 2 {
						name := parts[0]
						if sr := steps[name]; sr != nil {
							if n, err := strconv.Atoi(parts[1]); err == nil {
								sr.rc = n
							}
						}
					}
					current = ""
					continue
				}
				if current != "" {
					steps[current].lines = append(steps[current].lines, line)
				}
			}

			emit := func(name string) {
				sr := steps[name]
				out := ""
				rc := 0
				if sr != nil {
					out = strings.TrimSpace(strings.Join(sr.lines, "\n"))
					rc = sr.rc
				}
				var stepErr error
				if rc != 0 {
					stepErr = fmt.Errorf("command terminated with exit code %d", rc)
				}
				results <- netlabC9sLinuxScriptResult{
					Node:   node,
					Script: name,
					Stdout: out,
					Stderr: stderr,
					Err:    stepErr,
				}
			}

			emit("prep-interfaces")
			for _, s := range scripts {
				emit(s)
			}
			if enableSSH {
				emit("ssh")
			}
			if enableNoise {
				emit("noise")
			}
		}()
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

func linuxScriptModulesFromBinds(nodeCfg map[string]any) []string {
	if nodeCfg == nil {
		return nil
	}
	rawBinds, _ := nodeCfg["binds"].([]any)
	if len(rawBinds) == 0 {
		return nil
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(rawBinds))
	for _, bindAny := range rawBinds {
		bind := strings.TrimSpace(fmt.Sprintf("%v", bindAny))
		if bind == "" {
			continue
		}
		parts := strings.SplitN(bind, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hostPath := strings.TrimSpace(parts[0])
		targetPlusMode := strings.TrimSpace(parts[1])
		target := targetPlusMode
		if idx := strings.Index(targetPlusMode, ":"); idx >= 0 {
			target = strings.TrimSpace(targetPlusMode[:idx])
		}
		if !strings.HasSuffix(strings.ToLower(target), ".sh") {
			continue
		}

		module := strings.TrimSpace(path.Base(hostPath))
		if module == "" || strings.Contains(module, ".") {
			// Skip non-module file artifacts (for example startup.partial.config).
			continue
		}
		if seen[module] {
			continue
		}
		seen[module] = true
		out = append(out, module)
	}
	return out
}

func envBoolValue(raw string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return def
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return def
	}
}
