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
		nativeMode := envBool(spec.Environment, "SKYFORGE_CLABERNETES_NATIVE_MODE", true)
		hostNetwork := envBool(spec.Environment, "SKYFORGE_CLABERNETES_HOST_NETWORK", false)
		forceNativeMode := envBool(spec.Environment, "SKYFORGE_CLABERNETES_FORCE_NATIVE_MODE", false)
		disableExpose := envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_EXPOSE", false)
		disableAutoExpose := envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_AUTO_EXPOSE", true)

		// Default away from LoadBalancer to avoid klipper-lb hostPort conflicts (80/443) that can
		// prevent ingress/traefik from scheduling.
		exposeType := normalizeClabernetesExposeType(envString(spec.Environment, "SKYFORGE_CLABERNETES_EXPOSE_TYPE"))
		if exposeType == "" && !disableExpose {
			exposeType = "ClusterIP"
		}

		disableNativeForCeos := envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_NATIVE_FOR_CEOS", false)
		// vrnetlab-style NOS containers (IOL/VIOS/NXOSv/etc) often assume they can "own" the
		// primary network interface (eth0) and may flush/reconfigure it.
		//
		// Historically this forced us into non-native (launcher/DIND) mode by default because
		// eth0 is the Kubernetes pod network interface, and losing it breaks reachability.
		//
		// With Skyforge's dedicated Multus management network (kube-system/vrnetlab-mgmt),
		// vrnetlab nodes can take over a secondary interface instead of eth0, so native mode
		// is enabled by default. Set SKYFORGE_CLABERNETES_DISABLE_NATIVE_FOR_VRNETLAB=true to
		// force DIND for these nodes if needed.
		disableNativeForVrnetlab := envBool(spec.Environment, "SKYFORGE_CLABERNETES_DISABLE_NATIVE_FOR_VRNETLAB", false)
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

		// Some NOS images can be finicky in native mode depending on host kernel/cgroup setup.
		// Keep this opt-in so that "native + no-DIND" is the default path.
		if nativeMode && disableNativeForCeos && !forceNativeMode && containerlabTopologyHasKind(spec.TopologyYAML, "ceos") {
			log.Infof("Clabernetes: disabling native mode for cEOS nodes (set SKYFORGE_CLABERNETES_FORCE_NATIVE_MODE=true to override)")
			nativeMode = false
		}
		if nativeMode && disableNativeForVrnetlab && !forceNativeMode {
			vrKinds := []string{
				"cisco_iol",
				"cisco_vios",
				"cisco_viosl2",
				"vr-n9kv",
				"cisco_asav",
				"vr-vmx",
				"vr-sros",
				"vr-csr",
			}
			for _, k := range vrKinds {
				if containerlabTopologyHasKind(spec.TopologyYAML, k) {
					log.Infof("Clabernetes: disabling native mode for %s nodes (set SKYFORGE_CLABERNETES_DISABLE_NATIVE_FOR_VRNETLAB=false or SKYFORGE_CLABERNETES_FORCE_NATIVE_MODE=true to override)", k)
					nativeMode = false
					break
				}
			}
		}

		deployment := map[string]any{
			"nativeMode":  nativeMode,
			"hostNetwork": hostNetwork,
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

		if len(deployment) > 0 {
			payload["spec"].(map[string]any)["deployment"] = deployment
		}
		if err := kubeCreateClabernetesTopology(ctx, ns, payload); err != nil {
			return err
		}

		started := time.Now()
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
				if topo != nil && topo.Status.TopologyReady {
					log.Infof("Topology is ready (elapsed %s)", time.Since(started).Truncate(time.Second))

					// Best-effort: capture a topology graph artifact after deploy so the UI can render
					// resolved management IPs from clabernetes pods.
					if err := e.captureClabernetesTopologyArtifact(ctx, spec, name); err != nil {
						log.Infof("clabernetes topology capture failed: %v", err)
					}
					return nil
				}
				if time.Since(started) >= 15*time.Minute {
					return fmt.Errorf("clabernetes deploy timed out after %s", time.Since(started).Truncate(time.Second))
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

func (e *Engine) captureClabernetesTopologyArtifact(ctx context.Context, spec clabernetesRunSpec, topologyOwner string) error {
	if e == nil || spec.TaskID <= 0 {
		return fmt.Errorf("invalid task context")
	}
	if strings.TrimSpace(spec.WorkspaceID) == "" {
		// Best-effort enhancement: storing topology graphs requires a workspace scope.
		// Skip silently rather than failing the overall run.
		return nil
	}
	ns := strings.TrimSpace(spec.Namespace)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	topologyOwner = strings.TrimSpace(topologyOwner)
	if topologyOwner == "" {
		return fmt.Errorf("topology owner label is required")
	}

	pods, err := kubeListPods(ctx, ns, map[string]string{
		"clabernetes/topologyOwner": topologyOwner,
	})
	if err != nil {
		return err
	}
	podInfo := map[string]TopologyNode{}
	podNetworkStatus := map[string]string{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			continue
		}
		podNetworkStatus[node] = strings.TrimSpace(pod.Metadata.Annotations["k8s.v1.cni.cncf.io/network-status"])
		podInfo[node] = TopologyNode{
			ID:     node,
			Label:  node,
			MgmtIP: strings.TrimSpace(pod.Status.PodIP),
			Status: strings.TrimSpace(pod.Status.Phase),
		}
	}

	graph, err := containerlabYAMLBytesToTopologyGraph([]byte(spec.TopologyYAML), podInfo)
	if err != nil {
		return err
	}
	for i := range graph.Nodes {
		kind := strings.ToLower(strings.TrimSpace(graph.Nodes[i].Kind))
		switch kind {
		case "cisco_iol", "vios", "viosl2", "vr-n9kv", "asav", "vmx", "sros", "csr":
			raw := podNetworkStatus[strings.TrimSpace(graph.Nodes[i].ID)]
			if ip, ok := parseCNIStatusIPForNetwork(raw, "vrnetlab-mgmt"); ok {
				graph.Nodes[i].MgmtIP = ip
			}
		}
	}
	graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	graphBytes, err := json.Marshal(graph)
	if err != nil {
		return err
	}

	labName := strings.TrimSpace(spec.LabName)
	if labName == "" {
		labName = topologyOwner
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
