package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
	"gopkg.in/yaml.v3"
)

type netlabC9sTaskSpec struct {
	Action          string            `json:"action,omitempty"` // deploy|destroy
	Server          string            `json:"server,omitempty"`
	Deployment      string            `json:"deployment,omitempty"`
	DeploymentID    string            `json:"deploymentId,omitempty"`
	WorkspaceRoot   string            `json:"workspaceRoot,omitempty"`
	TemplateSource  string            `json:"templateSource,omitempty"`
	TemplateRepo    string            `json:"templateRepo,omitempty"`
	TemplatesDir    string            `json:"templatesDir,omitempty"`
	Template        string            `json:"template,omitempty"`
	WorkspaceDir    string            `json:"workspaceDir,omitempty"`
	MultilabNumeric int               `json:"multilabNumeric,omitempty"`
	TopologyPath    string            `json:"topologyPath,omitempty"`
	ClabTarball     string            `json:"clabTarball,omitempty"`
	K8sNamespace    string            `json:"k8sNamespace,omitempty"`
	LabName         string            `json:"labName,omitempty"`
	TopologyName    string            `json:"topologyName,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
}

type netlabC9sRunSpec struct {
	TaskID          int
	WorkspaceCtx    *workspaceContext
	WorkspaceSlug   string
	Username        string
	Environment     map[string]string
	Action          string
	Deployment      string
	DeploymentID    string
	WorkspaceRoot   string
	TemplateSource  string
	TemplateRepo    string
	TemplatesDir    string
	Template        string
	WorkspaceDir    string
	MultilabNumeric int
	StateRoot       string
	Server          NetlabServerConfig
	TopologyPath    string
	ClabTarball     string
	K8sNamespace    string
	LabName         string
	TopologyName    string
}

func tarballNameFromSpec(spec netlabC9sRunSpec) string {
	tarballName := strings.TrimSpace(spec.ClabTarball)
	if tarballName == "" {
		tarballName = fmt.Sprintf("containerlab-%s.tar.gz", strings.TrimSpace(spec.Deployment))
	}
	return tarballName
}

func clabernetesWorkspaceNamespace(workspaceSlug string) string {
	workspaceSlug = strings.TrimSpace(workspaceSlug)
	if workspaceSlug == "" {
		return "ws"
	}
	return sanitizeKubeNameFallback("ws-"+workspaceSlug, "ws")
}

func clabernetesTopologyName(labName string) string {
	labName = strings.TrimSpace(labName)
	if labName == "" {
		return "topology"
	}
	return sanitizeKubeNameFallback(labName, "topology")
}

func (e *Engine) dispatchNetlabC9sTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn netlabC9sTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	ws, err := e.loadWorkspaceByKey(ctx, task.WorkspaceID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &workspaceContext{
		workspace: *ws,
		claims: SessionClaims{
			Username: username,
		},
	}
	// NOTE: netlab-c9s is cluster-native and must not depend on BYOS netlab servers.

	if strings.TrimSpace(specIn.TemplateSource) == "" {
		specIn.TemplateSource = "blueprints"
	}

	runSpec := netlabC9sRunSpec{
		TaskID:          task.ID,
		WorkspaceCtx:    pc,
		WorkspaceSlug:   strings.TrimSpace(pc.workspace.Slug),
		Username:        username,
		Environment:     specIn.Environment,
		Action:          strings.TrimSpace(specIn.Action),
		Deployment:      strings.TrimSpace(specIn.Deployment),
		DeploymentID:    strings.TrimSpace(specIn.DeploymentID),
		WorkspaceRoot:   strings.TrimSpace(specIn.WorkspaceRoot),
		TemplateSource:  strings.TrimSpace(specIn.TemplateSource),
		TemplateRepo:    strings.TrimSpace(specIn.TemplateRepo),
		TemplatesDir:    strings.TrimSpace(specIn.TemplatesDir),
		Template:        strings.TrimSpace(specIn.Template),
		WorkspaceDir:    strings.TrimSpace(specIn.WorkspaceDir),
		MultilabNumeric: specIn.MultilabNumeric,
		StateRoot:       "",
		Server:          NetlabServerConfig{},
		TopologyPath:    strings.TrimSpace(specIn.TopologyPath),
		ClabTarball:     strings.TrimSpace(specIn.ClabTarball),
		K8sNamespace:    strings.TrimSpace(specIn.K8sNamespace),
		LabName:         strings.TrimSpace(specIn.LabName),
		TopologyName:    strings.TrimSpace(specIn.TopologyName),
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "netlab.c9s."+action, func() error {
		return e.runNetlabC9sTask(ctx, runSpec, log)
	})
}

func (e *Engine) runNetlabC9sTask(ctx context.Context, spec netlabC9sRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("netlab c9s job canceled")
		}
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}

	action := strings.ToLower(strings.TrimSpace(spec.Action))
	switch action {
	case "", "deploy", "create", "start", "up":
		action = "deploy"
	case "destroy", "delete", "down", "stop":
		action = "destroy"
	default:
		return fmt.Errorf("invalid netlab c9s action (use deploy or destroy)")
	}

	ns := strings.TrimSpace(spec.K8sNamespace)
	if ns == "" {
		ns = clabernetesWorkspaceNamespace(spec.WorkspaceCtx.workspace.Slug)
	}
	labName := strings.TrimSpace(spec.LabName)
	if labName == "" {
		labName = containerlabLabName(spec.WorkspaceCtx.workspace.Slug, spec.Deployment)
	}
	topologyName := strings.TrimSpace(spec.TopologyName)
	if topologyName == "" {
		topologyName = clabernetesTopologyName(labName)
	}

	if action == "destroy" {
		clabSpec := clabernetesRunSpec{
			TaskID:       spec.TaskID,
			Action:       "destroy",
			Namespace:    ns,
			TopologyName: topologyName,
			LabName:      labName,
		}
		if err := e.runClabernetesTask(ctx, clabSpec, log); err != nil {
			return err
		}
		log.Infof("Cleaning orphaned c9s resources (topologyOwner=%s)", topologyName)
		if err := kubeDeleteOrphanedClabernetesResources(ctx, ns, topologyName); err != nil {
			return err
		}
		log.Infof("Orphaned c9s resources cleanup requested")
		deleted, err := kubeDeleteConfigMapsByLabel(ctx, ns, map[string]string{
			"skyforge-c9s-topology": topologyName,
		})
		if err != nil {
			return err
		}
		if deleted > 0 {
			log.Infof("C9s configmaps deleted: %d", deleted)
		}
		return nil
	}

	if strings.TrimSpace(spec.Template) == "" {
		return fmt.Errorf("netlab template is required")
	}
	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return err
	}

	topologyPath := strings.TrimSpace(spec.TopologyPath)
	if topologyPath == "" {
		// When we pass a bundle, the netlab API server writes topology.yml in the workdir.
		topologyPath = "topology.yml"
	}
	var clabYAML []byte
	var nodeMounts map[string][]c9sFileFromConfigMap
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.k8s-generate", func() error {
		var err error
		clabYAML, nodeMounts, err = e.runNetlabC9sTaskK8sGenerator(ctx, spec, topologyPath, tarballNameFromSpec(spec), log)
		return err
	}); err != nil {
		return err
	}

	topologyBytes, nodeMounts, nodeNameMapping, err := prepareC9sTopologyForDeploy(spec.TaskID, topologyName, labName, clabYAML, nodeMounts, e, log)
	if err != nil {
		return err
	}

	// Prefer startup-config injection for EOS/cEOS (instead of post-start exec hacks).
	// This keeps netlab as the source-of-truth but lets Skyforge adapt the generated output
	// for clabernetes-native execution (files are mounted into the launcher, not the NOS container).
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.eos-startup-config", func() error {
		var err error
		topologyBytes, nodeMounts, err = injectNetlabC9sEOSStartupConfig(ctx, ns, topologyName, topologyBytes, nodeMounts, log)
		return err
	}); err != nil {
		return err
	}

	// Ensure SSH is reachable on IOS/IOS-XE nodes that use a dedicated management VRF.
	// Without this, SSH can be "enabled" but not listening in the mgmt VRF, causing
	// Forward connectivity tests to hang on TCP connect.
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.iosxe-ssh-vrf", func() error {
		var err error
		topologyBytes, nodeMounts, err = injectNetlabC9sIOSXEServerVRF(ctx, ns, topologyName, topologyBytes, nodeMounts, log)
		return err
	}); err != nil {
		return err
	}

	clabSpec := clabernetesRunSpec{
		TaskID:             spec.TaskID,
		WorkspaceID:        strings.TrimSpace(spec.WorkspaceCtx.workspace.ID),
		Action:             "deploy",
		Namespace:          ns,
		TopologyName:       topologyName,
		LabName:            labName,
		TopologyYAML:       string(topologyBytes),
		Environment:        spec.Environment,
		FilesFromConfigMap: nodeMounts,
	}
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "c9s.deploy", func() error {
		return e.runClabernetesTask(ctx, clabSpec, log)
	}); err != nil {
		return err
	}

	// Run netlab-generated Linux configuration scripts (initial + routing) directly
	// inside the Linux pods. This mirrors netlab's "faster without Ansible" workflow.
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.linux-scripts", func() error {
		// Enable SSH on linux hosts by default so they can be used as Forward CLI endpoints.
		// Can be disabled per-run via env.
		enableLinuxSSH := envBool(spec.Environment, "SKYFORGE_NETLAB_C9S_LINUX_ENABLE_SSH", true)
		return runNetlabC9sLinuxScripts(ctx, ns, topologyName, topologyBytes, nodeMounts, enableLinuxSSH, log)
	}); err != nil {
		return err
	}

	// Capture a lightweight topology graph after deploy so the UI can render
	// resolved management IPs without querying netlab output.
	graph, err := e.captureC9sTopologyArtifact(ctx, spec, ns, topologyName, labName, topologyBytes, nodeNameMapping, log)
	if err != nil {
		// Don't fail the run if topology capture fails; it is a best-effort UX enhancement.
		if log != nil {
			log.Infof("c9s topology capture failed: %v", err)
		}
	} else if graph != nil {
		// Apply post-up config for supported NOS kinds (cfglets, SSH enable, etc).
		// This must happen before Forward collection starts.
		if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.nos-postup", func() error {
			return runNetlabC9sNOSPostUp(ctx, ns, topologyName, topologyBytes, nodeMounts, log)
		}); err != nil && log != nil {
			// Best-effort: lab is still usable even if cfglets fail.
			log.Infof("c9s post-up config failed (ignored): %v", err)
		}

		dep, depErr := e.loadDeployment(ctx, spec.WorkspaceCtx.workspace.ID, strings.TrimSpace(spec.DeploymentID))
		if depErr != nil {
			if log != nil {
				log.Infof("forward sync skipped: failed to load deployment: %v", depErr)
			}
			goto artifacts
		}
		if dep == nil {
			if log != nil {
				log.Infof("forward sync skipped: deployment not found")
			}
			goto artifacts
		}

		// Import classic devices into Forward as soon as we have management IPs so Forward
		// can start its own reachability checks early. Do not start collection yet; it
		// should begin only after post-up config has been applied.
		if _, err := e.syncForwardTopologyGraphDevices(ctx, spec.TaskID, spec.WorkspaceCtx, dep, graph, forwardSyncOptions{
			StartCollection: false,
		}); err != nil && log != nil {
			log.Infof("forward sync skipped: %v", err)
		}

		// Wait for SSH readiness before starting Forward collection.
		// Some NOSs (notably cEOS) take additional time after the topology reports "ready"
		// before SSH is actually reachable.
		if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "forward.ready", func() error {
			timeoutSeconds := envInt(spec.Environment, "SKYFORGE_FORWARD_SYNC_WAIT_SECONDS", 180)
			if timeoutSeconds <= 0 {
				return nil
			}
			return waitForForwardSSHReady(ctx, spec.TaskID, e, graph, time.Duration(timeoutSeconds)*time.Second, log)
		}); err != nil {
			if log != nil {
				log.Infof("forward sync skipped: %v", err)
			}
			goto artifacts
		}

		_ = taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "forward.collection.start", func() error {
			return e.startForwardCollectionForDeployment(ctx, spec.TaskID, spec.WorkspaceCtx, dep)
		})
	}

	// Store a bundle of generated artifacts in object storage for browsing and debugging.
	// This is best-effort and should never fail the deployment run.
artifacts:
	_ = taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.artifacts", func() error {
		err := storeNetlabC9sArtifacts(ctx, e.cfg, netlabC9sArtifactsSpec{
			TaskID:        spec.TaskID,
			WorkspaceID:   strings.TrimSpace(spec.WorkspaceCtx.workspace.ID),
			TopologyName:  topologyName,
			LabName:       labName,
			Namespace:     ns,
			ClabYAMLRaw:   clabYAML,
			TopologyYAML:  topologyBytes,
			TopologyGraph: graph,
			NodeMounts:    nodeMounts,
		}, log)
		if err != nil && log != nil {
			log.Infof("netlab-c9s artifact upload failed: %v", err)
		}
		return nil
	})

	return nil
}

func envInt(env map[string]string, key string, def int) int {
	raw := strings.TrimSpace(envString(env, key))
	if raw == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(raw, "%d", &n)
	if err != nil {
		return def
	}
	return n
}

func waitForForwardSSHReady(ctx context.Context, taskID int, e *Engine, graph *TopologyGraph, timeout time.Duration, log Logger) error {
	if graph == nil {
		return nil
	}
	if timeout <= 0 {
		return nil
	}

	// Only gate on NOS nodes we intend to sync into Forward. Linux hosts are handled
	// separately (as endpoints) and should not block network creation.
	//
	// Note: vrnetlab-based nodes use a dedicated Multus mgmt network (vrnetlab-mgmt)
	// whose IP range is not routable from Skyforge worker pods by default. In that
	// case, a "local tcp dial" SSH readiness check will always time out even though
	// the in-cluster Forward collector can reach the nodes (it is Multus-attached).
	// We therefore skip the preflight SSH readiness gate for vrnetlab-based kinds and
	// let Forward perform its own reachability/collection retries.
	targets := make([]TopologyNode, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		kind := strings.ToLower(strings.TrimSpace(n.Kind))
		if kind == "" {
			// If kind is missing, assume it is a NOS node.
			kind = "unknown"
		}
		if kind == "linux" {
			continue
		}
		switch kind {
		case "cisco_iol", "vios", "viosl2", "vr-n9kv", "asav", "vmx", "sros", "csr":
			continue
		}
		if strings.TrimSpace(n.MgmtIP) == "" {
			continue
		}
		targets = append(targets, n)
	}
	if len(targets) == 0 {
		return nil
	}

	deadline := time.Now().Add(timeout)
	for _, node := range targets {
		node := node
		for {
			if time.Now().After(deadline) {
				return fmt.Errorf("forward sync wait timed out waiting for ssh on %s (%s)", strings.TrimSpace(node.Label), strings.TrimSpace(node.MgmtIP))
			}
			if taskID > 0 && e != nil {
				canceled, _ := e.taskCanceled(ctx, taskID)
				if canceled {
					return fmt.Errorf("forward sync wait canceled")
				}
			}

			ctxDial, cancel := context.WithTimeout(ctx, 2*time.Second)
			conn, err := (&net.Dialer{}).DialContext(ctxDial, "tcp", net.JoinHostPort(strings.TrimSpace(node.MgmtIP), "22"))
			cancel()
			if err == nil && conn != nil {
				_ = conn.Close()
				break
			}
			time.Sleep(2 * time.Second)
		}
	}

	if log != nil {
		log.Infof("forward ssh readiness ok: nodes=%d", len(targets))
	}
	return nil
}

func (e *Engine) captureC9sTopologyArtifact(ctx context.Context, spec netlabC9sRunSpec, ns, topologyName, labName string, topologyYAML []byte, nodeNameMapping map[string]string, log Logger) (*TopologyGraph, error) {
	if e == nil || e.db == nil || spec.TaskID <= 0 || spec.WorkspaceCtx == nil || strings.TrimSpace(spec.WorkspaceCtx.workspace.ID) == "" {
		return nil, fmt.Errorf("invalid task context")
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" {
		return nil, fmt.Errorf("namespace and topology name are required")
	}

	// Build a node->kind map so we can pick the correct management IP (podIP vs.
	// vrnetlab mgmt IP). vrnetlab nodes often remove the IP from the secondary
	// interface (net1) because the *VM* owns that IP, so we must sync Forward using
	// that VM mgmt IP (reachable via the vrnetlab-mgmt L2 segment), not the pod IP.
	nodeKind := map[string]string{}
	{
		var topo map[string]any
		if err := yaml.Unmarshal(topologyYAML, &topo); err == nil {
			if t, ok := topo["topology"].(map[string]any); ok {
				if nodesAny, ok := t["nodes"].(map[string]any); ok {
					for node, cfgAny := range nodesAny {
						nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
						cfg, ok := cfgAny.(map[string]any)
						if !ok || cfg == nil || nodeName == "" {
							continue
						}
						kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
						if kind == "" {
							continue
						}
						nodeKind[nodeName] = kind
					}
				}
			}
		}
	}
	isVrnetlabKind := func(k string) bool {
		k = strings.ToLower(strings.TrimSpace(k))
		switch k {
		case "cisco_iol", "iol",
			"cisco_vios", "vios",
			"cisco_viosl2", "viosl2",
			"vr-n9kv", "nxos", "nxosv",
			"cisco_asav", "asav", "asa",
			"vr-vmx", "vmx",
			"vr-sros", "sros",
			"vr-csr", "csr",
			"vr-fortios", "fortios",
			"vr-ftosv", "ftosv",
			"juniper_vjunos-router", "vjunos-router",
			"juniper_vjunos-switch", "vjunos-switch",
			"juniper_vjunosevolved", "vjunosevolved":
			return true
		default:
			return false
		}
	}

	pods, err := kubeListPods(ctx, ns, map[string]string{
		"clabernetes/topologyOwner": topologyName,
	})
	if err != nil {
		return nil, err
	}
	podInfo := map[string]TopologyNode{}
	podNetworkStatus := map[string]string{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			continue
		}
		podNetworkStatus[node] = strings.TrimSpace(pod.Metadata.Annotations["k8s.v1.cni.cncf.io/network-status"])
		mgmtIP := strings.TrimSpace(pod.Status.PodIP)
		if isVrnetlabKind(nodeKind[node]) {
			if ip, ok := parseCNIStatusIPForNetwork(podNetworkStatus[node], "vrnetlab-mgmt"); ok {
				mgmtIP = strings.TrimSpace(ip)
			}
		}
		podInfo[node] = TopologyNode{
			ID:     node,
			Label:  node,
			MgmtIP: mgmtIP,
			Status: strings.TrimSpace(pod.Status.Phase),
		}
	}

	graph, err := containerlabYAMLBytesToTopologyGraph(topologyYAML, podInfo)
	if err != nil {
		return nil, err
	}
	if len(nodeNameMapping) > 0 {
		for i := range graph.Nodes {
			id := strings.TrimSpace(graph.Nodes[i].ID)
			if id == "" {
				continue
			}
			if orig := strings.TrimSpace(nodeNameMapping[id]); orig != "" {
				graph.Nodes[i].Label = orig
			}
		}
	}
	graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	graphBytes, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(labName) == "" {
		labName = topologyName
	}
	key := fmt.Sprintf("topology/netlab-c9s/%s.json", sanitizeArtifactKeySegment(labName))
	ctxPut, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	putKey, err := putWorkspaceArtifact(ctxPut, e.cfg, spec.WorkspaceCtx.workspace.ID, key, graphBytes, "application/json")
	if err != nil {
		if isObjectStoreNotConfigured(err) {
			if log != nil {
				log.Infof("c9s topology capture skipped: %v", err)
			}
			return graph, nil
		}
		return nil, err
	}
	e.setTaskMetadataKey(spec.TaskID, "topologyKey", putKey)
	if log != nil {
		log.Infof("c9s topology artifact stored: %s", putKey)
	}
	return graph, nil
}

func prepareC9sTopologyForDeploy(taskID int, topologyName, labName string, clabYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, e *Engine, log Logger) ([]byte, map[string][]c9sFileFromConfigMap, map[string]string, error) {
	if log == nil {
		log = noopLogger{}
	}
	labName = strings.TrimSpace(labName)
	topologyName = strings.TrimSpace(topologyName)
	if len(clabYAML) == 0 {
		return nil, nil, nil, fmt.Errorf("clab.yml is empty")
	}

	// Sanitize node names to DNS-1035 labels so clabernetes can derive K8s resource names.
	sanitizedYAML, mapping, err := sanitizeContainerlabYAMLForClabernetes(string(clabYAML))
	if err != nil {
		return nil, nil, nil, err
	}
	if sanitizedYAML != "" {
		clabYAML = []byte(sanitizedYAML)
	}
	reverseMapping := map[string]string{}
	for orig, sanitized := range mapping {
		orig = strings.TrimSpace(orig)
		sanitized = strings.TrimSpace(sanitized)
		if orig == "" || sanitized == "" {
			continue
		}
		reverseMapping[sanitized] = orig
	}
	if len(mapping) > 0 && len(nodeMounts) > 0 {
		out := map[string][]c9sFileFromConfigMap{}
		for node, mounts := range nodeMounts {
			newNode := strings.TrimSpace(node)
			if mapped, ok := mapping[newNode]; ok {
				newNode = mapped
			}
			if newNode == "" {
				continue
			}
			for i := range mounts {
				for old, newName := range mapping {
					mounts[i].FilePath = strings.ReplaceAll(mounts[i].FilePath, "/node_files/"+old+"/", "/node_files/"+newName+"/")
				}
			}
			out[newNode] = mounts
		}
		nodeMounts = out
	}

	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	if topo == nil {
		topo = map[string]any{}
	}
	if labName != "" {
		topo["name"] = labName
	}

	// Rewrite bind sources to the mounted file paths (only for node_files paths).
	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
				// Some netlab-generated binds (notably /etc/hosts) point at a directory that is
				// populated via filesFromConfigMap, where the actual file lives under
				// `<mountRoot>/node_files/<rel>/<configMapPath>`.
				filePathForMountDir := map[string]string{}
				if nodeMounts != nil {
					if mounts, ok := nodeMounts[nodeName]; ok {
						for _, m := range mounts {
							if strings.TrimSpace(m.FilePath) == "" || strings.TrimSpace(m.ConfigMapPath) == "" {
								continue
							}
							filePathForMountDir[m.FilePath] = path.Join(m.FilePath, m.ConfigMapPath)
						}
					}
				}

				// Rewrite startup-config if present.
				if sc, ok := cfg["startup-config"].(string); ok {
					sc = strings.TrimSpace(sc)
					if strings.HasPrefix(sc, "config/") {
						cfg["startup-config"] = path.Join(mountRoot, sc)
					}
				}

				bindsAny, ok := cfg["binds"]
				if !ok {
					// Even if no binds, we might have updated nodeMounts with startup-config
					nodes[node] = cfg
					continue
				}
				rawBinds, ok := bindsAny.([]any)
				if !ok || len(rawBinds) == 0 {
					nodes[node] = cfg
					continue
				}
				out := make([]any, 0, len(rawBinds))
				for _, bindAny := range rawBinds {
					bind := strings.TrimSpace(fmt.Sprintf("%v", bindAny))
					if bind == "" {
						continue
					}
					parts := strings.SplitN(bind, ":", 2)
					if len(parts) != 2 {
						out = append(out, bind)
						continue
					}
					hostPath := strings.TrimSpace(parts[0])
					rest := parts[1]

					// Kubernetes container runtimes mount volumes with recursive bind flags
					// (`MS_BIND|MS_REC`). When attempting to mount a single file onto `/etc/hosts`,
					// some runtimes treat this as an invalid recursive bind (ENOTDIR). The
					// /etc/hosts bind is nice-to-have for name resolution but not required for the
					// topology to boot, so drop it for linux containers.
					if kind == "linux" && strings.HasPrefix(strings.TrimSpace(rest), "/etc/hosts") {
						if e != nil {
							e.appendTaskWarning(taskID, fmt.Sprintf("c9s: skipped /etc/hosts bind for linux node %s (not supported by runtime)", nodeName))
						}
						continue
					}

					hostPath = strings.TrimPrefix(hostPath, "./")
					if strings.HasPrefix(hostPath, "node_files/") {
						newHost := path.Join(mountRoot, hostPath)
						// If the bind target is /etc/hosts, netlab expects the source to be a file,
						// but filesFromConfigMap materializes the file under a directory named by
						// the bind source. Rewrite to the materialized file path when possible.
						if strings.HasPrefix(rest, "/etc/hosts") {
							if fp, ok := filePathForMountDir[newHost]; ok && fp != "" {
								newHost = fp
							}
						}
						out = append(out, newHost+":"+rest)
						continue
					}
					if strings.HasPrefix(hostPath, "config/") {
						newHost := path.Join(mountRoot, hostPath)
						out = append(out, newHost+":"+rest)
						continue
					}
					if !strings.HasPrefix(hostPath, "/") && hostPath != "" {
						if e != nil {
							e.appendTaskWarning(taskID, fmt.Sprintf("c9s: bind path %q for node %s is relative and not under node_files or config", hostPath, nodeName))
						}
					}
					out = append(out, bind)
				}
				cfg["binds"] = out
				nodes[node] = cfg
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
	}

	topologyBytes, err := yaml.Marshal(topo)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode clab.yml: %w", err)
	}
	return topologyBytes, nodeMounts, reverseMapping, nil
}

func ensureNetlabC9sEOSStartupSSH(ctx context.Context, ns, topologyName string, clabYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, log Logger) (map[string][]c9sFileFromConfigMap, error) {
	if log == nil {
		log = noopLogger{}
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" || len(clabYAML) == 0 || nodeMounts == nil {
		return nodeMounts, nil
	}

	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return nil, fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	topology, ok := topo["topology"].(map[string]any)
	if !ok {
		return nodeMounts, nil
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || len(nodes) == 0 {
		return nodeMounts, nil
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	overrideCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-startup-overrides", topologyName), "c9s-startup-overrides")
	overrideData := map[string]string{}
	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}

	changedAny := false
	for node, nodeAny := range nodes {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind != "ceos" && kind != "eos" {
			continue
		}
		sc, _ := cfg["startup-config"].(string)
		sc = strings.TrimSpace(sc)
		if !strings.HasPrefix(sc, "config/") {
			continue
		}

		startupPath := path.Join(mountRoot, sc)
		mounts := nodeMounts[nodeName]
		if len(mounts) == 0 {
			continue
		}

		var originalCM, originalKey string
		for _, m := range mounts {
			if strings.TrimSpace(m.FilePath) == startupPath && strings.TrimSpace(m.ConfigMapName) != "" && strings.TrimSpace(m.ConfigMapPath) != "" {
				originalCM = strings.TrimSpace(m.ConfigMapName)
				originalKey = strings.TrimSpace(m.ConfigMapPath)
				break
			}
		}
		if originalCM == "" || originalKey == "" {
			log.Infof("c9s: eos startup-config mount not found for %s (%s)", nodeName, sc)
			continue
		}

		cmData, ok, err := kubeGetConfigMap(ctx, ns, originalCM)
		if err != nil {
			return nil, err
		}
		if !ok {
			log.Infof("c9s: eos startup-config configmap missing: %s", originalCM)
			continue
		}
		contents, ok := cmData[originalKey]
		if !ok {
			log.Infof("c9s: eos startup-config key missing: %s/%s", originalCM, originalKey)
			continue
		}

		out, changed := injectEOSManagementSSH(contents)
		if !changed {
			continue
		}

		overrideKey := sanitizeArtifactKeySegment(fmt.Sprintf("%s-%s", nodeName, path.Base(sc)))
		if overrideKey == "" || overrideKey == "unknown" {
			overrideKey = sanitizeArtifactKeySegment(fmt.Sprintf("%s-startup", nodeName))
		}
		overrideData[overrideKey] = out

		for i := range mounts {
			if strings.TrimSpace(mounts[i].FilePath) == startupPath && strings.TrimSpace(mounts[i].ConfigMapName) == originalCM && strings.TrimSpace(mounts[i].ConfigMapPath) == originalKey {
				mounts[i].ConfigMapName = overrideCM
				mounts[i].ConfigMapPath = overrideKey
				changedAny = true
				break
			}
		}
		nodeMounts[nodeName] = mounts
	}

	if len(overrideData) == 0 || !changedAny {
		return nodeMounts, nil
	}
	if err := kubeUpsertConfigMap(ctx, ns, overrideCM, overrideData, labels); err != nil {
		return nil, err
	}
	log.Infof("c9s: injected management ssh into eos startup-config (%d file(s))", len(overrideData))
	return nodeMounts, nil
}

func injectEOSManagementSSH(cfg string) (out string, changed bool) {
	cfg = strings.ReplaceAll(cfg, "\r\n", "\n")
	lower := strings.ToLower(cfg)
	if strings.Contains(lower, "management ssh") {
		return cfg, false
	}

	lines := strings.Split(cfg, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(strings.ToLower(lines[i])) == "end" {
			outLines := make([]string, 0, len(lines)+1)
			outLines = append(outLines, lines[:i]...)
			outLines = append(outLines, "management ssh")
			outLines = append(outLines, lines[i:]...)
			out = strings.Join(outLines, "\n")
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			return out, true
		}
	}
	if !strings.HasSuffix(cfg, "\n") {
		cfg += "\n"
	}
	return cfg + "management ssh\n", true
}

func injectEOSDefaultSSHUser(cfg string) (out string, changed bool) {
	cfg = strings.ReplaceAll(cfg, "\r\n", "\n")
	lower := strings.ToLower(cfg)
	needUser := !(strings.Contains(lower, "\nusername ") || strings.HasPrefix(strings.TrimSpace(lower), "username "))
	needEnableSecret := !strings.Contains(lower, "\nenable secret")
	needAAALogin := !strings.Contains(lower, "\naaa authentication login")
	needAAAExec := !strings.Contains(lower, "\naaa authorization exec")

	if !needUser && !needEnableSecret && !needAAALogin && !needAAAExec {
		return cfg, false
	}

	linesToInsert := make([]string, 0, 4)
	// Default, predictable access for in-cluster labs. If a template supplies any of
	// these, we leave it alone.
	if needUser {
		linesToInsert = append(linesToInsert, "username admin privilege 15 secret admin")
	}
	if needEnableSecret {
		linesToInsert = append(linesToInsert, "enable secret admin")
	}
	if needAAALogin {
		linesToInsert = append(linesToInsert, "aaa authentication login default local")
	}
	if needAAAExec {
		linesToInsert = append(linesToInsert, "aaa authorization exec default local")
	}
	if len(linesToInsert) == 0 {
		return cfg, false
	}

	lines := strings.Split(cfg, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(strings.ToLower(lines[i])) == "end" {
			outLines := make([]string, 0, len(lines)+len(linesToInsert))
			outLines = append(outLines, lines[:i]...)
			outLines = append(outLines, linesToInsert...)
			outLines = append(outLines, lines[i:]...)
			out = strings.Join(outLines, "\n")
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			return out, true
		}
	}

	if !strings.HasSuffix(cfg, "\n") {
		cfg += "\n"
	}
	return cfg + strings.Join(linesToInsert, "\n") + "\n", true
}
