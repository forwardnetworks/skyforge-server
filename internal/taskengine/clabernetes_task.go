package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

func envBool(env map[string]string, key string, def bool) bool {
	if env == nil {
		return def
	}
	raw, ok := env[key]
	if !ok {
		return def
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return b
}

func envString(env map[string]string, key string) string {
	if env == nil {
		return ""
	}
	raw, ok := env[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(raw)
}

func envDuration(env map[string]string, key string, def time.Duration) time.Duration {
	raw := envString(env, key)
	if raw == "" {
		return def
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

type c9sFileFromConfigMap struct {
	ConfigMapName string `json:"configMapName,omitempty"`
	ConfigMapPath string `json:"configMapPath,omitempty"`
	FilePath      string `json:"filePath,omitempty"`
	Mode          string `json:"mode,omitempty"` // read|execute
}

type clabernetesTaskSpec struct {
	Action             string                            `json:"action,omitempty"`
	Namespace          string                            `json:"namespace,omitempty"`
	TopologyName       string                            `json:"topologyName,omitempty"`
	LabName            string                            `json:"labName,omitempty"`
	Template           string                            `json:"template,omitempty"`
	TopologyYAML       string                            `json:"topologyYAML,omitempty"`
	Environment        map[string]string                 `json:"environment,omitempty"`
	FilesFromConfigMap map[string][]c9sFileFromConfigMap `json:"filesFromConfigMap,omitempty"`
}

type clabernetesRunSpec struct {
	TaskID             int
	WorkspaceID        string
	Action             string
	Namespace          string
	TopologyName       string
	LabName            string
	Template           string
	TopologyYAML       string
	Environment        map[string]string
	FilesFromConfigMap map[string][]c9sFileFromConfigMap
}

func normalizeClabernetesExposeType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "none":
		return "None"
	case "clusterip", "cluster-ip":
		return "ClusterIP"
	case "loadbalancer", "load-balancer":
		return "LoadBalancer"
	default:
		return ""
	}
}

func (e *Engine) dispatchClabernetesTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn clabernetesTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	runSpec := clabernetesRunSpec{
		TaskID:             task.ID,
		WorkspaceID:        strings.TrimSpace(task.WorkspaceID),
		Action:             strings.TrimSpace(specIn.Action),
		Namespace:          strings.TrimSpace(specIn.Namespace),
		TopologyName:       strings.TrimSpace(specIn.TopologyName),
		LabName:            strings.TrimSpace(specIn.LabName),
		Template:           strings.TrimSpace(specIn.Template),
		TopologyYAML:       strings.TrimSpace(specIn.TopologyYAML),
		Environment:        specIn.Environment,
		FilesFromConfigMap: specIn.FilesFromConfigMap,
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "clabernetes."+action, func() error {
		return e.runClabernetesTask(ctx, runSpec, log)
	})
}

func (e *Engine) runClabernetesTask(ctx context.Context, spec clabernetesRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("clabernetes job canceled")
		}
	}
	ns := strings.TrimSpace(spec.Namespace)
	if ns == "" {
		return fmt.Errorf("k8s namespace is required")
	}
	name := strings.TrimSpace(spec.TopologyName)
	if name == "" {
		return fmt.Errorf("topology name is required")
	}

	switch strings.ToLower(strings.TrimSpace(spec.Action)) {
	case "deploy":
		log.Infof("Clabernetes deploy: namespace=%s topology=%s", ns, name)
		if err := kubeEnsureNamespace(ctx, ns); err != nil {
			return err
		}
		if err := kubeEnsureNamespaceImagePullSecret(ctx, ns, strings.TrimSpace(e.cfg.ImagePullSecretName), strings.TrimSpace(e.cfg.ImagePullSecretNamespace)); err != nil {
			return err
		}
		if _, err := kubeDeleteClabernetesTopology(ctx, ns, name); err != nil {
			return err
		}
		if len(spec.FilesFromConfigMap) > 0 {
			log.Infof("Clabernetes file mounts: nodes=%d", len(spec.FilesFromConfigMap))
		}
		connectivity := strings.ToLower(envString(spec.Environment, "SKYFORGE_CLABERNETES_CONNECTIVITY"))
		if connectivity == "" {
			// Default to VXLAN to support cross-node L2 adjacency.
			// (Multus bridge mode is node-local and cannot provide cross-node L2.)
			connectivity = "vxlan"
		}
		if connectivity == "multus" {
			return fmt.Errorf("clabernetes connectivity=multus is not supported")
		}
		// Skyforge never supports Docker-in-Docker (non-native) mode; always run clabernetes in
		// native mode so NOS containers run directly as Kubernetes containers.
		nativeMode := true
		// Native-mode link precreate needs CAP_NET_ADMIN in the launcher setup init container.
		// Default this on to avoid veth creation failures ("RTNETLINK ... Operation not permitted").
		privilegedLauncher := envBool(spec.Environment, "SKYFORGE_CLABERNETES_PRIVILEGED_LAUNCHER", true)
		hostNetwork := envBool(spec.Environment, "SKYFORGE_CLABERNETES_HOST_NETWORK", false)
		disableExpose := envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_EXPOSE", false)
		// Default to auto-exposing so clabernetes creates per-node ClusterIP services for
		// management ports defined in topology.defaults.ports (injected by Skyforge).
		disableAutoExpose := envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_AUTO_EXPOSE", false)

		// Default away from LoadBalancer to avoid klipper-lb hostPort conflicts (80/443) that can
		// prevent ingress/traefik from scheduling.
		exposeType := normalizeClabernetesExposeType(envString(spec.Environment, "SKYFORGE_CLABERNETES_EXPOSE_TYPE"))
		if exposeType == "" && !disableExpose {
			exposeType = "ClusterIP"
		}

		// Ensure clabernetes launcher pods can pull private images (launcher/NOS) by wiring the
		// namespace pull secret into the topology service account via spec.imagePull.pullSecrets.
		secretName := strings.TrimSpace(e.cfg.ImagePullSecretName)
		if secretName == "" {
			secretName = "ghcr-pull"
		}

		payload := map[string]any{
			"apiVersion": "clabernetes.containerlab.dev/v1alpha1",
			"kind":       "Topology",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
				"labels": map[string]any{
					"skyforge-managed": "true",
				},
			},
			"spec": map[string]any{
				"definition": map[string]any{
					"containerlab": spec.TopologyYAML,
				},
				"imagePull": map[string]any{
					"pullSecrets":  []any{secretName},
					"dockerConfig": secretName + "-docker-config",
				},
			},
		}

		if spec.TopologyYAML != "" {
			sanitized, mapping, err := sanitizeContainerlabYAMLForClabernetes(spec.TopologyYAML)
			if err != nil {
				return err
			}
			if sanitized != "" {
				spec.TopologyYAML = sanitized
				payload["spec"].(map[string]any)["definition"].(map[string]any)["containerlab"] = spec.TopologyYAML
			}
			if len(mapping) > 0 && len(spec.FilesFromConfigMap) > 0 {
				out := map[string][]c9sFileFromConfigMap{}
				for node, mounts := range spec.FilesFromConfigMap {
					newNode := strings.TrimSpace(node)
					if mapped, ok := mapping[newNode]; ok {
						newNode = mapped
					}
					if newNode == "" {
						continue
					}
					for i := range mounts {
						// Keep file paths consistent with sanitized node names.
						for old, newName := range mapping {
							mounts[i].FilePath = strings.ReplaceAll(mounts[i].FilePath, "/node_files/"+old+"/", "/node_files/"+newName+"/")
						}
					}
					out[newNode] = mounts
				}
				spec.FilesFromConfigMap = out
			}
		}
		if connectivity != "" {
			payload["spec"].(map[string]any)["connectivity"] = connectivity
		}

		// clabernetes expects scheduling overrides under spec.deployment.scheduling (not spec.scheduling).
		// We accumulate them here and attach to the deployment block later.
		var deploymentScheduling map[string]any
		ensureDeploymentScheduling := func() map[string]any {
			if deploymentScheduling == nil {
				deploymentScheduling = map[string]any{}
			}
			return deploymentScheduling
		}

		// Optional: pin topology pods to a specific Kubernetes node (hard requirement).
		// clabernetes exposes this as a "scheduling" block.
		if node := envString(spec.Environment, "SKYFORGE_CLABERNETES_NODE_SELECTOR_HOSTNAME"); node != "" {
			s := ensureDeploymentScheduling()
			s["nodeSelector"] = map[string]any{
				"kubernetes.io/hostname": node,
			}
		}

		// Optional: prefer (but do not require) scheduling topology pods onto a specific node.
		// This is useful to co-locate workloads with a per-user sidecar/collector when possible,
		// while still allowing normal cluster spreading.
		if node := envString(spec.Environment, "SKYFORGE_CLABERNETES_PREFERRED_NODE_HOSTNAME"); node != "" {
			scheduling := ensureDeploymentScheduling()
			scheduling["affinity"] = map[string]any{
				"nodeAffinity": map[string]any{
					"preferredDuringSchedulingIgnoredDuringExecution": []any{
						map[string]any{
							"weight": 100,
							"preference": map[string]any{
								"matchExpressions": []any{
									map[string]any{
										"key":      "kubernetes.io/hostname",
										"operator": "In",
										"values":   []any{node},
									},
								},
							},
						},
					},
				},
			}
		}

		// Default: prefer spreading per-topology pods across Kubernetes nodes.
		//
		// Large NOS images (vrnetlab/QEMU) can be CPU-heavy. If all nodes in a topology schedule
		// onto the same Kubernetes worker, SSH responsiveness and Forward collection can degrade
		// significantly (slow read rates, timeouts, etc.). We therefore apply a soft pod
		// anti-affinity rule keyed on clabernetes' own topology owner label.
		//
		// This remains "preferred" (not required) so small clusters can still schedule labs.
		//
		// NOTE: For performance benchmarking and "EVE-NG-like" density, operators may want to
		// *pack* all pods on a single node. Use SKYFORGE_CLABERNETES_SCHEDULING_MODE=pack|spread
		// to select the default behavior (pack is the default).
		schedulingMode := strings.ToLower(envString(spec.Environment, "SKYFORGE_CLABERNETES_SCHEDULING_MODE"))
		if schedulingMode == "" {
			schedulingMode = "pack"
		}
		requireAntiAffinity := envBool(spec.Environment, "SKYFORGE_CLABERNETES_POD_ANTI_AFFINITY_REQUIRED", false)
		enableAntiAffinity := envBool(spec.Environment, "SKYFORGE_CLABERNETES_ENABLE_POD_ANTI_AFFINITY", schedulingMode == "spread")
		//
		// NOTE: The upstream clabernetes Topology CRD in our deployment prunes affinity from
		// spec.deployment.scheduling, so we cannot rely on writing affinity into the Topology
		// spec and having it persist. Instead, we pass scheduling intent via a label and let
		// our clabernetes-manager fork apply the corresponding Pod affinity at render time.
		if requireAntiAffinity || enableAntiAffinity {
			labelsAny, _ := payload["metadata"].(map[string]any)["labels"].(map[string]any)
			if labelsAny == nil {
				labelsAny = map[string]any{}
				payload["metadata"].(map[string]any)["labels"] = labelsAny
			}
			const labelKey = "skyforge.forwardnetworks.com/scheduling"
			if requireAntiAffinity {
				labelsAny[labelKey] = "spread-required"
				log.Infof("Clabernetes scheduling: require spreading pods (podAntiAffinity required topologyOwner=%s)", name)
			} else {
				labelsAny[labelKey] = "spread-preferred"
				log.Infof("Clabernetes scheduling: prefer spreading pods (podAntiAffinity topologyOwner=%s)", name)
			}
		}

		if disableExpose {
			payload["spec"].(map[string]any)["expose"] = map[string]any{
				"disableExpose": true,
			}
		} else if exposeType != "" {
			payload["spec"].(map[string]any)["expose"] = map[string]any{
				"exposeType":        exposeType,
				"disableAutoExpose": disableAutoExpose,
			}
		}

		if containerlabTopologyHasKind(spec.TopologyYAML, "ceos") {
			// Historically, cEOS could be finicky in some native-mode setups. Skyforge does not
			// support falling back to Docker-in-Docker; surface a clear error if this is hit so
			// we can address native compatibility instead of silently switching runtimes.
			if envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_NATIVE_FOR_CEOS", false) {
				return fmt.Errorf("cEOS native mode is required; Docker-in-Docker is not supported")
			}
		}

		deployment := map[string]any{
			"nativeMode":         nativeMode,
			"hostNetwork":        hostNetwork,
			"privilegedLauncher": privilegedLauncher,
		}

		if len(spec.FilesFromConfigMap) > 0 {
			files := map[string]any{}
			for node, entries := range spec.FilesFromConfigMap {
				node = strings.TrimSpace(node)
				if node == "" || len(entries) == 0 {
					continue
				}
				out := make([]any, 0, len(entries))
				for _, entry := range entries {
					if strings.TrimSpace(entry.ConfigMapName) == "" || strings.TrimSpace(entry.FilePath) == "" {
						continue
					}
					item := map[string]any{
						"configMapName": strings.TrimSpace(entry.ConfigMapName),
						"filePath":      strings.TrimSpace(entry.FilePath),
					}
					if strings.TrimSpace(entry.ConfigMapPath) != "" {
						item["configMapPath"] = strings.TrimSpace(entry.ConfigMapPath)
					}
					if strings.TrimSpace(entry.Mode) != "" {
						item["mode"] = strings.TrimSpace(entry.Mode)
					}
					out = append(out, item)
				}
				if len(out) > 0 {
					files[node] = out
				}
			}
			if len(files) > 0 {
				deployment["filesFromConfigMap"] = files
			}
		}

		if deploymentScheduling != nil && len(deploymentScheduling) > 0 {
			deployment["scheduling"] = deploymentScheduling
		}

		// Optional: apply per-node Kubernetes resource requests for common NOS kinds.
		// This improves scheduler placement and CPU share allocation, and helps avoid
		// pathological "slow SSH read rates" caused by severe CPU contention.
		//
		// NOTE: clabernetes expects these under spec.deployment.resources (not spec.resources).
		if envBool(spec.Environment, "SKYFORGE_CLABERNETES_ENABLE_RESOURCES", true) && strings.TrimSpace(spec.TopologyYAML) != "" {
			kinds, err := containerlabNodeKinds(spec.TopologyYAML)
			if err != nil {
				log.Infof("Clabernetes resources: parse failed (ignored): %v", err)
			} else if len(kinds) > 0 {
				enableLimits := envBool(spec.Environment, "SKYFORGE_CLABERNETES_ENABLE_LIMITS", false)
				resources := map[string]any{}
				for nodeName, kind := range kinds {
					profile, ok := nosResourceProfileForKind(kind)
					if !ok {
						continue
					}
					req := map[string]any{}
					if strings.TrimSpace(profile.CPURequest) != "" {
						req["cpu"] = strings.TrimSpace(profile.CPURequest)
					}
					if strings.TrimSpace(profile.MemoryRequest) != "" {
						req["memory"] = strings.TrimSpace(profile.MemoryRequest)
					}
					rr := map[string]any{}
					if len(req) > 0 {
						rr["requests"] = req
					}
					if enableLimits {
						lim := map[string]any{}
						if strings.TrimSpace(profile.CPULimit) != "" {
							lim["cpu"] = strings.TrimSpace(profile.CPULimit)
						}
						if strings.TrimSpace(profile.MemoryLimit) != "" {
							lim["memory"] = strings.TrimSpace(profile.MemoryLimit)
						}
						if len(lim) > 0 {
							rr["limits"] = lim
						}
					}
					if len(rr) > 0 {
						resources[nodeName] = rr
					}
				}
				if len(resources) > 0 {
					deployment["resources"] = resources
					log.Infof("Clabernetes resources: configured nodes=%d", len(resources))
				}
			}
		}

		// Persist deployment overrides after all optional mutations (files, resources, etc).
		if len(deployment) > 0 {
			payload["spec"].(map[string]any)["deployment"] = deployment
		}

		if err := kubeCreateClabernetesTopology(ctx, ns, payload); err != nil {
			return err
		}

		started := time.Now()
		deployTimeout := envDuration(spec.Environment, "SKYFORGE_CLABERNETES_DEPLOY_TIMEOUT", 15*time.Minute)
		if deployTimeout < 30*time.Second {
			deployTimeout = 30 * time.Second
		}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("clabernetes deploy canceled")
			case <-ticker.C:
				if spec.TaskID > 0 {
					canceled, _ := e.taskCanceled(ctx, spec.TaskID)
					if canceled {
						return fmt.Errorf("clabernetes job canceled")
					}
				}
				topo, _, err := kubeGetClabernetesTopology(ctx, ns, name)
				if err != nil {
					log.Errorf("Topology status error: %v", err)
					continue
				}

				podsReady := false
				var podsNotReady []string
				if topo != nil {
					ready, notReady, err := kubeClabernetesTopologyPodsReady(ctx, ns, name)
					if err != nil {
						log.Infof("clabernetes pod readiness check failed: %v", err)
					} else {
						podsReady = ready
						podsNotReady = notReady
					}
				}

				if topo != nil && (topo.Status.TopologyReady || podsReady) {
					if topo.Status.TopologyReady {
						log.Infof("Topology is ready (elapsed %s)", time.Since(started).Truncate(time.Second))
					} else {
						log.Infof("Topology not marked ready by clabernetes yet, but all topology pods are Ready (elapsed %s)", time.Since(started).Truncate(time.Second))
					}

					// Validate we actually landed in clabernetes native mode. If this fails, the
					// topology will be running Docker-in-Docker inside the launcher, which Skyforge
					// never supports due to performance/compatibility concerns.
					log.Infof("Clabernetes native mode: validating (no Docker-in-Docker)")
					if err := kubeAssertClabernetesNativeMode(ctx, ns, name); err != nil {
						return err
					}
					log.Infof("Clabernetes native mode: verified")

					// Optional: assert that cross-node VXLAN is actually being exercised. This is
					// primarily used by E2E smoke to ensure we don't regress into node-local wiring.
					if envBool(spec.Environment, "SKYFORGE_E2E_VXLAN_SMOKE", false) || envBool(spec.Environment, "SKYFORGE_CLABERNETES_VXLAN_SMOKE", false) {
						log.Infof("Clabernetes vxlan smoke: checking overlay wiring")
						nodes, err := kubeClabernetesVXLANSmokeCheck(ctx, ns, name)
						if err != nil {
							return err
						}
						log.Infof("Clabernetes vxlan smoke: ok (nodes=%d)", nodes)
					}

					// Capture a topology graph artifact after deploy so the UI can render resolved
					// management IPs from clabernetes pods.
					graph, err := e.resolveClabernetesTopologyGraph(ctx, spec, name)
					if err != nil {
						log.Infof("clabernetes topology graph resolve failed: %v", err)
					} else if graph != nil {
						if err := e.storeClabernetesTopologyArtifact(ctx, spec, graph); err != nil {
							log.Infof("clabernetes topology capture failed: %v", err)
						}

						// Wait until NOS nodes are actually SSH-ready before marking the deploy step complete.
						// This avoids "ready too fast" and prevents downstream systems (Forward sync, UI terminal)
						// from racing long boot times.
						sshReadySeconds := envInt(spec.Environment, "SKYFORGE_CLABERNETES_SSH_READY_SECONDS", 900)
						if sshReadySeconds > 0 {
							if err := waitForForwardSSHReady(ctx, spec.TaskID, e, graph, time.Duration(sshReadySeconds)*time.Second, log); err != nil {
								return err
							}
						}
					}
					return nil
				}

				if time.Since(started) >= deployTimeout {
					return fmt.Errorf("clabernetes deploy timed out after %s", time.Since(started).Truncate(time.Second))
				}
				if len(podsNotReady) > 0 {
					// Keep logs terse and stable; list a small sample of not-ready pods.
					if len(podsNotReady) > 3 {
						podsNotReady = podsNotReady[:3]
					}
					log.Infof("Clabernetes pod readiness: not ready yet (%s)", strings.Join(podsNotReady, "; "))
				}
				log.Infof("Waiting for topology to become ready (elapsed %s)", time.Since(started).Truncate(time.Second))
			}
		}
	case "destroy":
		log.Infof("Clabernetes destroy: namespace=%s topology=%s", ns, name)
		deleted, err := kubeDeleteClabernetesTopology(ctx, ns, name)
		if err != nil {
			return err
		}
		if !deleted {
			_ = kubeDeleteOrphanedClabernetesResources(ctx, ns, name)
			log.Infof("Topology not found; destroy treated as success.")
			return nil
		}
		started := time.Now()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("clabernetes destroy canceled")
			case <-ticker.C:
				if spec.TaskID > 0 {
					canceled, _ := e.taskCanceled(ctx, spec.TaskID)
					if canceled {
						return fmt.Errorf("clabernetes job canceled")
					}
				}
				topo, status, err := kubeGetClabernetesTopology(ctx, ns, name)
				if err != nil {
					log.Errorf("Topology status error: %v", err)
					continue
				}
				if topo == nil && status == http.StatusNotFound {
					log.Infof("Topology deleted (elapsed %s)", time.Since(started).Truncate(time.Second))
					log.Infof("Cleaning orphaned clabernetes resources (topologyOwner=%s)", name)
					_ = kubeDeleteOrphanedClabernetesResources(ctx, ns, name)
					return nil
				}
				if time.Since(started) >= 5*time.Minute {
					return fmt.Errorf("clabernetes destroy timed out after %s", time.Since(started).Truncate(time.Second))
				}
				log.Infof("Waiting for topology deletion (elapsed %s)", time.Since(started).Truncate(time.Second))
			}
		}
	default:
		return fmt.Errorf("unknown clabernetes action")
	}
}

func (e *Engine) resolveClabernetesTopologyGraph(ctx context.Context, spec clabernetesRunSpec, topologyOwner string) (*TopologyGraph, error) {
	if e == nil || spec.TaskID <= 0 {
		return nil, fmt.Errorf("invalid task context")
	}
	ns := strings.TrimSpace(spec.Namespace)
	if ns == "" {
		return nil, fmt.Errorf("namespace is required")
	}
	topologyOwner = strings.TrimSpace(topologyOwner)
	if topologyOwner == "" {
		return nil, fmt.Errorf("topology owner label is required")
	}

	pods, err := kubeListPods(ctx, ns, map[string]string{
		"clabernetes/topologyOwner": topologyOwner,
	})
	if err != nil {
		return nil, err
	}
	podInfo := map[string]TopologyNode{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			continue
		}
		svcName := fmt.Sprintf("%s-%s", topologyOwner, node)
		podInfo[node] = TopologyNode{
			ID:       node,
			Label:    node,
			MgmtIP:   strings.TrimSpace(pod.Status.PodIP),
			MgmtHost: kubeServiceFQDN(svcName, ns),
			PingIP:   strings.TrimSpace(pod.Status.PodIP),
			Status:   strings.TrimSpace(pod.Status.Phase),
		}
	}

	graph, err := containerlabYAMLBytesToTopologyGraph([]byte(spec.TopologyYAML), podInfo)
	if err != nil {
		return nil, err
	}
	graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return graph, nil
}

func (e *Engine) storeClabernetesTopologyArtifact(ctx context.Context, spec clabernetesRunSpec, graph *TopologyGraph) error {
	if e == nil || spec.TaskID <= 0 || graph == nil {
		return fmt.Errorf("invalid task context")
	}
	if strings.TrimSpace(spec.WorkspaceID) == "" {
		// Best-effort enhancement: storing topology graphs requires a workspace scope.
		// Skip silently rather than failing the overall run.
		return nil
	}

	graphBytes, err := json.Marshal(graph)
	if err != nil {
		return err
	}

	labName := strings.TrimSpace(spec.LabName)
	if labName == "" {
		labName = "clabernetes"
	}
	if labName == "" {
		labName = "clabernetes"
	}
	key := fmt.Sprintf("topology/clabernetes/%s.json", sanitizeArtifactKeySegment(labName))
	ctxPut, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	putKey, err := putWorkspaceArtifact(ctxPut, e.cfg, spec.WorkspaceID, key, graphBytes, "application/json")
	if err != nil {
		if isObjectStoreNotConfigured(err) {
			return nil
		}
		return err
	}
	e.setTaskMetadataKey(spec.TaskID, "topologyKey", putKey)
	return nil
}
