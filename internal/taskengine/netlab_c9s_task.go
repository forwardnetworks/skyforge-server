package taskengine

import (
	"context"
	"fmt"
	"path"
	"strings"

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

	serverRef := strings.TrimSpace(specIn.Server)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if serverRef == "" {
		// backward-compat fallback
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := e.resolveWorkspaceNetlabServer(ctx, pc.workspace.ID, serverRef)
	if err != nil {
		return err
	}

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
		StateRoot:       strings.TrimSpace(server.StateRoot),
		Server:          *server,
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

	// 1) Run netlab create to generate clab.yml + node_files.
	netlabCreate := netlabRunSpec{
		TaskID:          spec.TaskID,
		WorkspaceCtx:    spec.WorkspaceCtx,
		WorkspaceSlug:   spec.WorkspaceSlug,
		Username:        spec.Username,
		Environment:     spec.Environment,
		Action:          "create",
		Deployment:      spec.Deployment,
		DeploymentID:    spec.DeploymentID,
		WorkspaceRoot:   spec.WorkspaceRoot,
		TemplateSource:  spec.TemplateSource,
		TemplateRepo:    spec.TemplateRepo,
		TemplatesDir:    spec.TemplatesDir,
		Template:        spec.Template,
		WorkspaceDir:    spec.WorkspaceDir,
		MultilabNumeric: spec.MultilabNumeric,
		StateRoot:       spec.StateRoot,
		Server:          spec.Server,
		TopologyPath:    topologyPath,
	}
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.create", func() error {
		return e.runNetlabTask(ctx, netlabCreate, log)
	}); err != nil {
		return err
	}

	// 2) Run netlab clab-tarball to export node_files + clab.yml.
	tarballName := strings.TrimSpace(spec.ClabTarball)
	if tarballName == "" {
		tarballName = fmt.Sprintf("containerlab-%s.tar.gz", strings.TrimSpace(spec.Deployment))
	}
	netlabTar := netlabRunSpec{
		TaskID:          spec.TaskID,
		WorkspaceCtx:    spec.WorkspaceCtx,
		WorkspaceSlug:   spec.WorkspaceSlug,
		Username:        spec.Username,
		Environment:     spec.Environment,
		Action:          "clab-tarball",
		Deployment:      spec.Deployment,
		DeploymentID:    spec.DeploymentID,
		WorkspaceRoot:   spec.WorkspaceRoot,
		TemplateSource:  spec.TemplateSource,
		TemplateRepo:    spec.TemplateRepo,
		TemplatesDir:    spec.TemplatesDir,
		Template:        spec.Template,
		WorkspaceDir:    spec.WorkspaceDir,
		MultilabNumeric: spec.MultilabNumeric,
		StateRoot:       spec.StateRoot,
		Server:          spec.Server,
		TopologyPath:    topologyPath,
		ClabTarball:     tarballName,
	}
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.clab-tarball", func() error {
		return e.runNetlabTask(ctx, netlabTar, log)
	}); err != nil {
		return err
	}

	apiURL := netlabAPIURL(spec.Server)
	if apiURL == "" {
		return fmt.Errorf("netlab api url is not configured")
	}
	auth, err := e.netlabAPIAuthForUser(spec.Username, spec.Server)
	if err != nil {
		return err
	}
	jobID, ok, err := e.getTaskMetadataString(ctx, spec.TaskID, "netlabJobId")
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(jobID) == "" {
		return fmt.Errorf("netlab job id unavailable for tarball download")
	}
	tarBytes, err := netlabAPIGetJobArtifact(ctx, apiURL, jobID, tarballName, spec.Server.APIInsecure, auth)
	if err != nil {
		return err
	}
	tarball, err := extractNetlabC9sTarball(tarBytes)
	if err != nil {
		return err
	}

	// 3) Prepare containerlab topology for C9s. Set lab name and rewrite node_files binds to absolute paths.
	var topo map[string]any
	if err := yaml.Unmarshal(tarball.ClabYAML, &topo); err != nil {
		return fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	if topo == nil {
		topo = map[string]any{}
	}
	topo["name"] = labName

	// Ensure minimal Linux containers (typically Alpine-based) have sshd running so
	// SSH connectivity and Forward credential sync work out of the box.
	linuxSSHExec := `sh -c 'pgrep sshd >/dev/null 2>&1 && exit 0 || true; if command -v sshd >/dev/null 2>&1; then :; elif command -v apk >/dev/null 2>&1; then apk add --no-cache openssh-server openssh-client >/dev/null 2>&1 || apk add --no-cache openssh-server >/dev/null 2>&1 || true; elif command -v apt-get >/dev/null 2>&1; then apt-get update -qq >/dev/null 2>&1 || true; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 || true; fi; mkdir -p /var/run/sshd >/dev/null 2>&1 || true; ssh-keygen -A >/dev/null 2>&1 || true; printf \"\\nPermitRootLogin yes\\nPasswordAuthentication yes\\n\" >> /etc/ssh/sshd_config 2>/dev/null || true; echo root:admin | chpasswd >/dev/null 2>&1 || true; ( /usr/sbin/sshd -e 2>/dev/null || sshd -e 2>/dev/null || true )'`
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
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
					if strings.Contains(fmt.Sprintf("%v", item), "linux ssh") || strings.Contains(fmt.Sprintf("%v", item), "openssh-server") {
						already = true
						break
					}
				}
				if !already {
					out = append(out, linuxSSHExec)
				}
				cfg["exec"] = out
				nodes[node] = cfg
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	nodeMounts := map[string][]c9sFileFromConfigMap{}
	for node, files := range tarball.NodeFiles {
		if len(files) == 0 {
			continue
		}
		total := 0
		cmData := map[string]string{}
		mounts := make([]c9sFileFromConfigMap, 0, len(files))
		for rel, payload := range files {
			rel = strings.TrimSpace(rel)
			if rel == "" || len(payload) == 0 {
				continue
			}
			total += len(payload)
			key := strings.NewReplacer("/", "__", ":", "_", "\\", "_").Replace(rel)
			if key == "" {
				continue
			}
			if _, exists := cmData[key]; exists {
				continue
			}
			cmData[key] = string(payload)
			mountPath := path.Join(mountRoot, "node_files", node, rel)
			mounts = append(mounts, c9sFileFromConfigMap{
				ConfigMapName: c9sConfigMapName(topologyName, node),
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
		if total > 900<<10 {
			return fmt.Errorf("node_files for %s too large for a ConfigMap (%d bytes)", node, total)
		}
		if len(cmData) == 0 || len(mounts) == 0 {
			continue
		}
		if err := kubeUpsertConfigMap(ctx, ns, c9sConfigMapName(topologyName, node), cmData, map[string]string{
			"skyforge-c9s-topology": topologyName,
			"skyforge-c9s-node":     node,
		}); err != nil {
			return err
		}
		nodeMounts[node] = mounts
	}

	// Rewrite bind sources to the mounted file paths (only for node_files paths).
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				bindsAny, ok := cfg["binds"]
				if !ok {
					continue
				}
				rawBinds, ok := bindsAny.([]any)
				if !ok || len(rawBinds) == 0 {
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
					hostPath = strings.TrimPrefix(hostPath, "./")
					if strings.HasPrefix(hostPath, "node_files/") {
						newHost := path.Join(mountRoot, hostPath)
						out = append(out, newHost+":"+rest)
						continue
					}
					if !strings.HasPrefix(hostPath, "/") && hostPath != "" {
						e.appendTaskWarning(spec.TaskID, fmt.Sprintf("c9s: bind path %q for node %s is relative and not under node_files", hostPath, nodeName))
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
		return fmt.Errorf("failed to encode clab.yml: %w", err)
	}

	clabSpec := clabernetesRunSpec{
		TaskID:             spec.TaskID,
		Action:             "deploy",
		Namespace:          ns,
		TopologyName:       topologyName,
		LabName:            labName,
		TopologyYAML:       string(topologyBytes),
		Environment:        spec.Environment,
		FilesFromConfigMap: nodeMounts,
	}
	return taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "c9s.deploy", func() error {
		return e.runClabernetesTask(ctx, clabSpec, log)
	})
}
