package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
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

	topologyBytes, nodeMounts, err := prepareC9sTopologyForDeploy(spec.TaskID, topologyName, labName, clabYAML, nodeMounts, e, log)
	if err != nil {
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
		return runNetlabC9sLinuxScripts(ctx, ns, topologyName, topologyBytes, log)
	}); err != nil {
		return err
	}

	// Capture a lightweight topology graph after deploy so the UI can render
	// resolved management IPs without querying netlab output.
	graph, err := e.captureC9sTopologyArtifact(ctx, spec, ns, topologyName, labName, topologyBytes, log)
	if err != nil {
		// Don't fail the run if topology capture fails; it is a best-effort UX enhancement.
		if log != nil {
			log.Infof("c9s topology capture failed: %v", err)
		}
	} else if graph != nil {
		if dep, err := e.loadDeployment(ctx, spec.WorkspaceCtx.workspace.ID, strings.TrimSpace(spec.DeploymentID)); err == nil && dep != nil {
			if _, err := e.syncForwardTopologyGraphDevices(ctx, spec.TaskID, spec.WorkspaceCtx, dep, graph); err != nil && log != nil {
				log.Infof("forward sync skipped: %v", err)
			}
		}
	}

	return nil
}

func (e *Engine) captureC9sTopologyArtifact(ctx context.Context, spec netlabC9sRunSpec, ns, topologyName, labName string, topologyYAML []byte, log Logger) (*TopologyGraph, error) {
	if e == nil || e.db == nil || spec.TaskID <= 0 || spec.WorkspaceCtx == nil || strings.TrimSpace(spec.WorkspaceCtx.workspace.ID) == "" {
		return nil, fmt.Errorf("invalid task context")
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" {
		return nil, fmt.Errorf("namespace and topology name are required")
	}

	pods, err := kubeListPods(ctx, ns, map[string]string{
		"clabernetes/topologyOwner": topologyName,
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
		podInfo[node] = TopologyNode{
			ID:     node,
			Label:  node,
			MgmtIP: strings.TrimSpace(pod.Status.PodIP),
			Status: strings.TrimSpace(pod.Status.Phase),
		}
	}

	graph, err := containerlabYAMLBytesToTopologyGraph(topologyYAML, podInfo)
	if err != nil {
		return nil, err
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

func prepareC9sTopologyForDeploy(taskID int, topologyName, labName string, clabYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, e *Engine, log Logger) ([]byte, map[string][]c9sFileFromConfigMap, error) {
	if log == nil {
		log = noopLogger{}
	}
	labName = strings.TrimSpace(labName)
	topologyName = strings.TrimSpace(topologyName)
	if len(clabYAML) == 0 {
		return nil, nil, fmt.Errorf("clab.yml is empty")
	}

	// Sanitize node names to DNS-1035 labels so clabernetes can derive K8s resource names.
	sanitizedYAML, mapping, err := sanitizeContainerlabYAMLForClabernetes(string(clabYAML))
	if err != nil {
		return nil, nil, err
	}
	if sanitizedYAML != "" {
		clabYAML = []byte(sanitizedYAML)
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
		return nil, nil, fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	if topo == nil {
		topo = map[string]any{}
	}
	if labName != "" {
		topo["name"] = labName
	}

	// Ensure minimal Linux containers (typically Alpine-based) have sshd running so
	// SSH connectivity and Forward credential sync work out of the box.
	linuxSSHExec := `sh -c 'pgrep sshd >/dev/null 2>&1 && exit 0 || true; if command -v sshd >/dev/null 2>&1; then :; elif command -v apk >/dev/null 2>&1; then apk add --no-cache openssh-server openssh-client >/dev/null 2>&1 || apk add --no-cache openssh-server >/dev/null 2>&1 || true; elif command -v apt-get >/dev/null 2>&1; then apt-get update -qq >/dev/null 2>&1 || true; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 || true; fi; mkdir -p /var/run/sshd >/dev/null 2>&1 || true; ssh-keygen -A >/dev/null 2>&1 || true; printf \"\\nPermitRootLogin yes\\nPasswordAuthentication yes\\n\" >> /etc/ssh/sshd_config 2>/dev/null || true; echo root:admin | chpasswd >/dev/null 2>&1 || true; ( /usr/sbin/sshd -e 2>/dev/null || sshd -e 2>/dev/null || true )'`
	// Netlab expects Arista cEOS nodes to be reachable via SSH for Ansible readiness/config.
	// In some environments (notably native clabernetes mode), SSH may be disabled by default.
	// Inject a best-effort post-start exec to enable management SSH once the EOS CLI is ready.
	ceosEnableSSHExec := `sh -c 'if ! command -v Cli >/dev/null 2>&1; then exit 0; fi; i=0; while [ $i -lt 120 ]; do Cli -p 15 -c \"show version\" >/dev/null 2>&1 && break; sleep 2; i=$((i+1)); done; Cli -p 15 -c \"enable\" -c \"configure terminal\" -c \"management ssh\" -c \"end\" -c \"write memory\" >/dev/null 2>&1 || true'`
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
				if kind == "ceos" || kind == "eos" {
					existingAny, _ := cfg["exec"]
					out := []any{}
					if existingList, ok := existingAny.([]any); ok {
						out = append(out, existingList...)
					}
					already := false
					for _, item := range out {
						if strings.Contains(strings.ToLower(fmt.Sprintf("%v", item)), "management ssh") {
							already = true
							break
						}
					}
					if !already {
						out = append(out, ceosEnableSSHExec)
					}
					cfg["exec"] = out
					nodes[node] = cfg
					continue
				}
				if kind != "linux" {
					continue
				}
				image := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))
				if image == "" || (!strings.Contains(image, "alpine") && !strings.HasPrefix(image, "python")) {
					continue
				}
				existingAny, _ := cfg["exec"]
				out := []any{}
				if existingList, ok := existingAny.([]any); ok {
					out = append(out, existingList...)
				}
				already := false
				for _, item := range out {
					if strings.Contains(fmt.Sprintf("%v", item), "openssh-server") {
						already = true
						break
					}
				}
				if !already {
					out = append(out, linuxSSHExec)
				}
				cfg["exec"] = out

				// Ensure the container stays running. Some base images (like python) exit quickly if
				// no command is provided, which causes clabernetes to repeatedly recreate pods.
				if strings.TrimSpace(fmt.Sprintf("%v", cfg["cmd"])) == "" {
					cfg["cmd"] = "sh -c 'sleep infinity'"
				}
				if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", cfg["restart-policy"])), "no") {
					cfg["restart-policy"] = "always"
				}

				nodes[node] = cfg
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
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
		return nil, nil, fmt.Errorf("failed to encode clab.yml: %w", err)
	}
	return topologyBytes, nodeMounts, nil
}
