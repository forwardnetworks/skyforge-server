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

func runNetlabC9sLinuxScripts(ctx context.Context, ns, topologyOwner string, topologyYAML []byte, log Logger) error {
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

	mountRoot := "/tmp/skyforge-c9s/" + topologyOwner
	scripts := []string{"initial", "routing"}

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	results := make(chan netlabC9sLinuxScriptResult, len(linuxNodes)*len(scripts))

	for _, node := range linuxNodes {
		node := strings.TrimSpace(node)
		podName := strings.TrimSpace(podByNode[node])
		if node == "" || podName == "" {
			continue
		}
		container := node // clabernetes uses topologyNode as the main container name

		for _, script := range scripts {
			script := script
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				scriptPath := fmt.Sprintf("%s/node_files/%s/%s", mountRoot, node, script)
				cmd := fmt.Sprintf("set -e; if [ -f %q ]; then chmod +x %q 2>/dev/null || true; sh %q; fi", scriptPath, scriptPath, scriptPath)
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
	}

	wg.Wait()
	close(results)

	var firstErr error
	for res := range results {
		if res.Err != nil {
			log.Errorf("netlab linux script failed node=%s script=%s err=%v stderr=%s", res.Node, res.Script, res.Err, res.Stderr)
			if firstErr == nil {
				firstErr = fmt.Errorf("linux script failed for %s (%s): %w", res.Node, res.Script, res.Err)
			}
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
	return firstErr
}
