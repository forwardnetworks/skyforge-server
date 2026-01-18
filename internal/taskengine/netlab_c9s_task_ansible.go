package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
)

func (e *Engine) runNetlabC9sAnsible(ctx context.Context, spec netlabC9sRunSpec, ns, topologyName, labName string, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if e == nil {
		return fmt.Errorf("engine unavailable")
	}
	if strings.TrimSpace(e.cfg.AnsibleRunnerImage) == "" {
		return fmt.Errorf("netlab-c9s ansible requested but AnsibleRunnerImage is not configured (set ENCORE_CFG_SKYFORGE.NetlabGenerator.AnsibleImage or SKYFORGE_ANSIBLE_RUNNER_IMAGE)")
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" {
		return fmt.Errorf("namespace and topology name are required")
	}

	return taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.ansible", func() error {
		manifestCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-manifest", topologyName), "c9s-manifest")
		data, ok, err := kubeGetConfigMap(ctx, ns, manifestCM)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("netlab-c9s manifest configmap not found: %s", manifestCM)
		}
		raw := strings.TrimSpace(data["manifest.json"])
		if raw == "" {
			return fmt.Errorf("netlab-c9s manifest is empty in %s", manifestCM)
		}
		var manifest netlabC9sManifest
		if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
			return fmt.Errorf("invalid netlab-c9s manifest: %w", err)
		}

		nodeNames := make([]string, 0, len(manifest.Nodes))
		for node := range manifest.Nodes {
			node = strings.TrimSpace(node)
			if node != "" {
				nodeNames = append(nodeNames, node)
			}
		}
		if len(nodeNames) == 0 {
			return fmt.Errorf("netlab-c9s manifest has no nodes")
		}

		// Prefer stable service DNS names over pod IPs.
		//
		// clabernetes creates one per-node "expose" Service (type configurable, but always gets a
		// stable ClusterIP) named "<topology>-<node>", where <node> must be a DNS-1035 label.
		//
		// netlab-generated node names can contain uppercase letters (L1/L2/etc); Skyforge sanitizes
		// the containerlab YAML before creating the Topology, so we must apply the same mapping here.
		nodeHosts := map[string]string{}
		_, mapping, err := sanitizeContainerlabYAMLForClabernetes(manifest.ClabYAML)
		if err != nil {
			return err
		}
		for _, node := range nodeNames {
			orig := strings.TrimSpace(node)
			if orig == "" {
				continue
			}
			sanitized := orig
			if mapping != nil {
				if v, ok := mapping[orig]; ok {
					sanitized = v
				}
			}
			// If the node name did not change, still ensure it's DNS-1035-safe.
			sanitized = sanitizeDNS1035Label(sanitized)
			svc := sanitizeDNS1035Label(fmt.Sprintf("%s-%s", topologyName, sanitized))
			nodeHosts[orig] = fmt.Sprintf("%s.%s.svc", svc, ns)
		}
		if len(nodeHosts) == 0 {
			return fmt.Errorf("failed to compute node host mapping for ansible")
		}
		nodeHostsJSON, _ := json.Marshal(nodeHosts)

		// Provide the same flattened topology bundle used by the generator; the ansible runner
		// re-runs `netlab create` to produce group_vars/host_vars and inventory, then patches
		// ansible_host values to the in-cluster service DNS names.
		bundleB64, err := e.buildNetlabTopologyBundleB64(ctx, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template)
		if err != nil {
			return err
		}
		bundleB64 = strings.TrimSpace(bundleB64)
		if bundleB64 == "" {
			return fmt.Errorf("netlab topology bundle is empty")
		}
		if len(bundleB64) > 900_000 {
			return fmt.Errorf("netlab topology bundle too large for ansible runner (%d bytes base64)", len(bundleB64))
		}

		labels := map[string]string{
			"skyforge-c9s-topology": topologyName,
		}
		bundleCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-bundle-ansible-%d", topologyName, time.Now().Unix()%10_000), "c9s-bundle")
		if err := kubeUpsertConfigMap(ctx, ns, bundleCM, map[string]string{"bundle.b64": bundleB64}, labels); err != nil {
			return err
		}
		defer func() { _, _ = kubeDeleteConfigMap(context.Background(), ns, bundleCM) }()

		jobName := sanitizeKubeNameFallback(fmt.Sprintf("netlab-ansible-%s-%d", topologyName, time.Now().Unix()%10_000), "netlab-ansible")
		image := strings.TrimSpace(e.cfg.AnsibleRunnerImage)
		pullPolicy := strings.TrimSpace(e.cfg.AnsibleRunnerPullPolicy)
		if pullPolicy == "" {
			pullPolicy = "IfNotPresent"
		}

		payload := map[string]any{
			"apiVersion": "batch/v1",
			"kind":       "Job",
			"metadata": map[string]any{
				"name":      jobName,
				"namespace": ns,
				"labels": map[string]any{
					"app":                   "skyforge-netlab-ansible",
					"skyforge-c9s-topology": topologyName,
					"skyforge-task-id":      fmt.Sprintf("%d", spec.TaskID),
				},
			},
			"spec": map[string]any{
				"backoffLimit":            0,
				"ttlSecondsAfterFinished": 3600,
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{
							"app": "skyforge-netlab-ansible",
						},
					},
					"spec": map[string]any{
						"restartPolicy": "Never",
						"containers": []map[string]any{
							{
								"name":            "ansible",
								"image":           image,
								"imagePullPolicy": pullPolicy,
								"env": kubeEnvList(map[string]string{
									"SKYFORGE_NETLAB_BUNDLE_PATH":     "/input/bundle.b64",
									"SKYFORGE_NETLAB_TOPOLOGY_PATH":   "topology.yml",
									"SKYFORGE_C9S_NAMESPACE":          ns,
									"SKYFORGE_C9S_TOPOLOGY_NAME":      topologyName,
									"SKYFORGE_C9S_LAB_NAME":           strings.TrimSpace(labName),
									"SKYFORGE_C9S_NODE_IPS_JSON":      string(nodeHostsJSON),
									"SKYFORGE_C9S_EXPECTED_NODE_LIST": strings.Join(nodeNames, ","),
								}),
								"volumeMounts": []map[string]any{
									{"name": "input", "mountPath": "/input", "readOnly": true},
									{"name": "work", "mountPath": "/work"},
								},
							},
						},
						"volumes": []map[string]any{
							{
								"name": "input",
								"configMap": map[string]any{
									"name": bundleCM,
								},
							},
							{
								"name": "work",
								"emptyDir": map[string]any{
									"sizeLimit": "2Gi",
								},
							},
						},
					},
				},
			},
		}

		if err := kubeCreateJob(ctx, ns, payload); err != nil {
			return err
		}
		defer func() { _ = kubeDeleteJob(context.Background(), ns, jobName) }()

		log.Infof("Netlab C9s ansible job created: %s", jobName)
		if err := kubeWaitStreamingJob(ctx, ns, jobName, log, func() bool {
			if spec.TaskID <= 0 || e == nil {
				return false
			}
			canceled, _ := e.taskCanceled(ctx, spec.TaskID)
			return canceled
		}, "Netlab C9s ansible"); err != nil {
			return err
		}

		log.Infof("Netlab C9s ansible phase complete.")
		return nil
	})
}

func kubeWaitStreamingJob(ctx context.Context, ns, name string, log Logger, canceled func() bool, heartbeatLabel string) error {
	if log == nil {
		log = noopLogger{}
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	started := time.Now()
	var lastHeartbeat time.Time
	var lastLog string
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s canceled", strings.TrimSpace(heartbeatLabel))
		case <-ticker.C:
			if canceled != nil && canceled() {
				_ = kubeDeleteJob(context.Background(), ns, name)
				return fmt.Errorf("%s canceled", strings.TrimSpace(heartbeatLabel))
			}
			status, err := kubeGetJobStatus(ctx, client, ns, name)
			if err != nil {
				log.Errorf("Job status error: %v", err)
			}
			if time.Since(lastHeartbeat) >= 30*time.Second {
				lastHeartbeat = time.Now()
				label := strings.TrimSpace(heartbeatLabel)
				if label == "" {
					label = "Job"
				}
				log.Infof("%s still running (elapsed %s)", label, time.Since(started).Truncate(time.Second))
			}
			if logs, err := kubeGetJobLogs(ctx, client, ns, name); err == nil {
				if len(logs) > len(lastLog) {
					appendJobLogs(logs[len(lastLog):], log)
					lastLog = logs
				}
			}
			if status.Failed > 0 {
				return fmt.Errorf("job failed: %s", tailLines(lastLog, 40))
			}
			if status.Succeeded > 0 {
				return nil
			}
		}
	}
}

func matchC9sNodeIPs(topologyName string, nodes []string, pods []kubePod) (map[string]string, error) {
	topologyName = strings.ToLower(strings.TrimSpace(topologyName))
	nodeIPs := map[string]string{}
	if len(nodes) == 0 {
		return nodeIPs, nil
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("no pods found in namespace")
	}

	type scoredPod struct {
		pod   kubePod
		score int
	}

	candidatesByNode := map[string][]scoredPod{}
	for _, node := range nodes {
		n := strings.ToLower(strings.TrimSpace(node))
		if n == "" {
			continue
		}
		candidatesByNode[n] = nil
	}

	for _, pod := range pods {
		name := strings.ToLower(strings.TrimSpace(pod.Metadata.Name))
		if name == "" {
			continue
		}
		base := 0
		if topologyName != "" && strings.Contains(name, topologyName) {
			base += 4
		}
		for _, owner := range pod.Metadata.OwnerReferences {
			if strings.EqualFold(strings.TrimSpace(owner.Name), topologyName) {
				base += 6
			}
		}
		for k, v := range pod.Metadata.Labels {
			if strings.Contains(strings.ToLower(k), "topology") && strings.EqualFold(strings.TrimSpace(v), topologyName) {
				base += 5
			}
		}
		if base == 0 {
			continue
		}

		for node := range candidatesByNode {
			score := base
			if strings.Contains(name, node) {
				score += 5
			} else {
				for _, v := range pod.Metadata.Labels {
					if strings.EqualFold(strings.TrimSpace(v), node) {
						score += 3
					}
				}
			}
			if score < base+3 {
				continue
			}
			candidatesByNode[node] = append(candidatesByNode[node], scoredPod{pod: pod, score: score})
		}
	}

	missing := make([]string, 0)
	for _, node := range nodes {
		key := strings.ToLower(strings.TrimSpace(node))
		if key == "" {
			continue
		}
		best := scoredPod{score: -1}
		for _, cand := range candidatesByNode[key] {
			ip := strings.TrimSpace(cand.pod.Status.PodIP)
			if ip == "" {
				continue
			}
			if cand.score > best.score {
				best = cand
			}
		}
		if best.score < 0 || strings.TrimSpace(best.pod.Status.PodIP) == "" {
			missing = append(missing, node)
			continue
		}
		nodeIPs[node] = strings.TrimSpace(best.pod.Status.PodIP)
	}

	if len(missing) > 0 {
		names := make([]string, 0, len(pods))
		for _, pod := range pods {
			if strings.TrimSpace(pod.Metadata.Name) != "" {
				names = append(names, pod.Metadata.Name)
			}
		}
		return nil, fmt.Errorf("unable to map node pods for topology %q (missing=%s; pods=%s)", topologyName, strings.Join(missing, ","), strings.Join(names, ","))
	}
	return nodeIPs, nil
}
