package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func decodeTaskSpec[T any](task *TaskRecord, out *T) error {
	if task == nil || out == nil {
		return fmt.Errorf("task unavailable")
	}
	raw, ok := task.Metadata["spec"]
	if !ok || len(raw) == 0 {
		return fmt.Errorf("task spec missing (retry the run)")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("task spec decode failed: %w", err)
	}
	return nil
}

func (s *Service) withTaskStep(ctx context.Context, taskID int, stepKey string, fn func() error) error {
	if s == nil || s.db == nil || taskID <= 0 {
		if fn == nil {
			return nil
		}
		return fn()
	}
	stepKey = strings.TrimSpace(stepKey)
	if stepKey == "" {
		stepKey = "step"
	}
	startedAt := time.Now()
	_ = appendTaskEvent(context.Background(), s.db, taskID, "task.step.started", map[string]any{
		"step": stepKey,
	})
	if fn == nil {
		_ = appendTaskEvent(context.Background(), s.db, taskID, "task.step.succeeded", map[string]any{
			"step":        stepKey,
			"duration_ms": time.Since(startedAt).Milliseconds(),
		})
		return nil
	}
	err := fn()
	if err != nil {
		_ = appendTaskEvent(context.Background(), s.db, taskID, "task.step.failed", map[string]any{
			"step":        stepKey,
			"duration_ms": time.Since(startedAt).Milliseconds(),
			"error":       strings.TrimSpace(err.Error()),
		})
		return err
	}
	_ = appendTaskEvent(context.Background(), s.db, taskID, "task.step.succeeded", map[string]any{
		"step":        stepKey,
		"duration_ms": time.Since(startedAt).Milliseconds(),
	})
	return nil
}

type netlabTaskSpec struct {
	Action          string            `json:"action,omitempty"`
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
	Cleanup         bool              `json:"cleanup,omitempty"`
	TopologyPath    string            `json:"topologyPath,omitempty"`
	ClabTarball     string            `json:"clabTarball,omitempty"`
	ClabConfigDir   string            `json:"clabConfigDir,omitempty"`
	ClabCleanup     bool              `json:"clabCleanup,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
}

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

func (s *Service) dispatchNetlabTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	var specIn netlabTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	pc, err := s.systemWorkspaceContext(ctx, task.WorkspaceID, task.CreatedBy)
	if err != nil {
		return err
	}
	serverName := strings.TrimSpace(specIn.Server)
	if serverName == "" {
		serverName = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if serverName == "" {
		serverName = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, _ := resolveNetlabServer(s.cfg, serverName)
	if server == nil {
		return fmt.Errorf("netlab runner is not configured")
	}

	if strings.TrimSpace(specIn.TemplateSource) == "" {
		specIn.TemplateSource = "blueprints"
	}

	runSpec := netlabRunSpec{
		TaskID:          task.ID,
		WorkspaceCtx:    pc,
		WorkspaceSlug:   pc.workspace.Slug,
		Username:        strings.TrimSpace(task.CreatedBy),
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
		Cleanup:         specIn.Cleanup,
		Server:          *server,
		TopologyPath:    strings.TrimSpace(specIn.TopologyPath),
		ClabTarball:     strings.TrimSpace(specIn.ClabTarball),
		ClabConfigDir:   strings.TrimSpace(specIn.ClabConfigDir),
		ClabCleanup:     specIn.ClabCleanup,
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return s.withTaskStep(ctx, task.ID, "netlab."+action, func() error {
		return s.runNetlabTask(ctx, runSpec, log)
	})
}

func (s *Service) dispatchNetlabC9sTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	var specIn netlabC9sTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	pc, err := s.systemWorkspaceContext(ctx, task.WorkspaceID, task.CreatedBy)
	if err != nil {
		return err
	}
	serverName := strings.TrimSpace(specIn.Server)
	if serverName == "" {
		serverName = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if serverName == "" {
		serverName = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, _ := resolveNetlabServer(s.cfg, serverName)
	if server == nil {
		return fmt.Errorf("netlab runner is not configured")
	}
	if strings.TrimSpace(specIn.TemplateSource) == "" {
		specIn.TemplateSource = "blueprints"
	}

	runSpec := netlabC9sRunSpec{
		TaskID:          task.ID,
		WorkspaceCtx:    pc,
		WorkspaceSlug:   pc.workspace.Slug,
		Username:        strings.TrimSpace(task.CreatedBy),
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
	return s.withTaskStep(ctx, task.ID, "netlab.c9s."+action, func() error {
		return s.runNetlabC9sTask(ctx, runSpec, log)
	})
}

type labppTaskSpec struct {
	Action            string            `json:"action,omitempty"`
	EveServer         string            `json:"eveServer,omitempty"`
	EveURL            string            `json:"eveUrl,omitempty"`
	EveUsername       string            `json:"eveUsername,omitempty"`
	EvePasswordEnc    string            `json:"evePasswordEnc,omitempty"`
	Deployment        string            `json:"deployment,omitempty"`
	DeploymentID      string            `json:"deploymentId,omitempty"`
	TemplatesRoot     string            `json:"templatesRoot,omitempty"`
	Template          string            `json:"template,omitempty"`
	LabPath           string            `json:"labPath,omitempty"`
	ThreadCount       int               `json:"threadCount,omitempty"`
	MaxSeconds        int               `json:"maxSeconds,omitempty"`
	Environment       map[string]string `json:"environment,omitempty"`
	TemplateSource    string            `json:"templateSource,omitempty"`
	TemplateRepo      string            `json:"templateRepo,omitempty"`
	TemplatesDir      string            `json:"templatesDir,omitempty"`
	TemplatesDestRoot string            `json:"templatesDestRoot,omitempty"`
}

func (s *Service) dispatchLabppTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	var specIn labppTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	pc, err := s.systemWorkspaceContext(ctx, task.WorkspaceID, task.CreatedBy)
	if err != nil {
		return err
	}

	serverName := strings.TrimSpace(specIn.EveServer)
	var eveServer *EveServerConfig
	if serverName != "" {
		eveServer = eveServerByName(s.cfg.EveServers, serverName)
	}
	if eveServer == nil && len(s.cfg.EveServers) > 0 {
		eveServer = &s.cfg.EveServers[0]
	}
	if eveServer == nil {
		return fmt.Errorf("eve server is not configured")
	}

	eveURL := strings.TrimSpace(specIn.EveURL)
	if eveURL == "" {
		eveURL = strings.TrimSpace(eveServer.WebURL)
		if eveURL == "" {
			eveURL = strings.TrimSpace(eveServer.APIURL)
		}
	}
	eveUsername := strings.TrimSpace(specIn.EveUsername)
	if eveUsername == "" {
		eveUsername = strings.TrimSpace(pc.claims.Username)
	}
	evePassword := ""
	if enc := strings.TrimSpace(specIn.EvePasswordEnc); enc != "" {
		if plaintext, err := decryptUserSecret(enc); err == nil {
			evePassword = strings.TrimSpace(plaintext)
		}
	}
	if evePassword == "" {
		if cached, ok := getCachedLDAPPassword(s.db, pc.claims.Username); ok {
			evePassword = strings.TrimSpace(cached)
		}
	}
	if strings.TrimSpace(eveUsername) == "" || strings.TrimSpace(evePassword) == "" {
		return fmt.Errorf("eve credentials are required (login again to refresh cached password)")
	}

	template := strings.TrimSpace(specIn.Template)
	if template == "" {
		return fmt.Errorf("template is required")
	}

	templatesRoot := strings.TrimSpace(specIn.TemplatesRoot)
	if templatesRoot == "" {
		source := strings.TrimSpace(specIn.TemplateSource)
		if source == "" {
			source = "blueprints"
		}
		syncedRoot := ""
		if err := s.withTaskStep(ctx, task.ID, "labpp.sync-template", func() error {
			out, err := s.syncLabppTemplateDir(
				ctx,
				pc,
				eveServer,
				source,
				strings.TrimSpace(specIn.TemplateRepo),
				strings.TrimSpace(specIn.TemplatesDir),
				template,
				strings.TrimSpace(specIn.TemplatesDestRoot),
			)
			syncedRoot = strings.TrimSpace(out)
			return err
		}); err != nil {
			return fmt.Errorf("failed to sync labpp template: %w", err)
		}
		templatesRoot = syncedRoot
	}

	labPath := strings.TrimSpace(specIn.LabPath)
	if labPath == "" {
		deployment := strings.TrimSpace(specIn.Deployment)
		if deployment == "" {
			deployment = strings.TrimSpace(pc.workspace.Slug)
		}
		labPath = labppLabPath(pc.claims.Username, deployment, template, time.Now())
		labPath = labppNormalizeFolderPath(labPath)
	}

	maxSeconds := specIn.MaxSeconds
	if maxSeconds <= 0 {
		maxSeconds = 1200
	}

	runSpec := labppRunSpec{
		TaskID:        task.ID,
		WorkspaceCtx:  pc,
		DeploymentID:  strings.TrimSpace(specIn.DeploymentID),
		Action:        strings.TrimSpace(specIn.Action),
		WorkspaceSlug: strings.TrimSpace(pc.workspace.Slug),
		Username:      strings.TrimSpace(pc.claims.Username),
		Deployment:    strings.TrimSpace(specIn.Deployment),
		Environment:   specIn.Environment,
		TemplatesRoot: templatesRoot,
		Template:      template,
		LabPath:       labPath,
		ThreadCount:   specIn.ThreadCount,
		EveURL:        eveURL,
		EveUsername:   eveUsername,
		EvePassword:   evePassword,
		MaxSeconds:    maxSeconds,
		Metadata:      task.Metadata,
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return s.withTaskStep(ctx, task.ID, "labpp."+action, func() error {
		return s.runLabppTask(ctx, runSpec, log)
	})
}

type containerlabTaskSpec struct {
	Action         string            `json:"action,omitempty"`
	NetlabServer   string            `json:"netlabServer,omitempty"`
	Deployment     string            `json:"deployment,omitempty"`
	LabName        string            `json:"labName,omitempty"`
	Reconfigure    bool              `json:"reconfigure,omitempty"`
	SkipTLS        bool              `json:"skipTls,omitempty"`
	TopologyJSON   string            `json:"topologyJSON,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	APIURL         string            `json:"apiUrl,omitempty"`
	Token          string            `json:"token,omitempty"`
	TemplateSource string            `json:"templateSource,omitempty"`
	TemplateRepo   string            `json:"templateRepo,omitempty"`
	TemplatesDir   string            `json:"templatesDir,omitempty"`
	Template       string            `json:"template,omitempty"`
}

func (s *Service) dispatchContainerlabTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	var specIn containerlabTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	pc, err := s.systemWorkspaceContext(ctx, task.WorkspaceID, task.CreatedBy)
	if err != nil {
		return err
	}
	apiURL := strings.TrimSpace(specIn.APIURL)
	token := strings.TrimSpace(specIn.Token)
	skipTLS := specIn.SkipTLS

	// Best-effort: if we didn't precompute API URL/token, derive it again.
	if apiURL == "" || token == "" {
		serverName := strings.TrimSpace(specIn.NetlabServer)
		if serverName == "" {
			serverName = strings.TrimSpace(pc.workspace.NetlabServer)
		}
		if serverName == "" {
			serverName = strings.TrimSpace(pc.workspace.EveServer)
		}
		server, _ := resolveNetlabServer(s.cfg, serverName)
		if server == nil {
			return fmt.Errorf("containerlab runner is not configured")
		}
		apiURL = containerlabAPIURL(s.cfg, *server)
		if apiURL == "" {
			return fmt.Errorf("containerlab api url is not configured")
		}
		var err error
		token, err = containerlabTokenForUser(s.cfg, pc.claims.Username)
		if err != nil {
			return fmt.Errorf("containerlab jwt secret is not configured")
		}
		skipTLS = containerlabSkipTLS(s.cfg, *server)
	}

	runSpec := containerlabRunSpec{
		TaskID:      task.ID,
		APIURL:      apiURL,
		Token:       token,
		Action:      strings.TrimSpace(specIn.Action),
		LabName:     strings.TrimSpace(specIn.LabName),
		Environment: specIn.Environment,
		Topology:    nil,
		Reconfigure: specIn.Reconfigure,
		SkipTLS:     skipTLS,
	}
	if strings.TrimSpace(specIn.TopologyJSON) != "" {
		if err := json.Unmarshal([]byte(specIn.TopologyJSON), &runSpec.Topology); err != nil {
			return fmt.Errorf("failed to decode containerlab topology")
		}
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return s.withTaskStep(ctx, task.ID, "containerlab."+action, func() error {
		return s.runContainerlabTask(ctx, runSpec, log)
	})
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

func (s *Service) dispatchClabernetesTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	var specIn clabernetesTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	runSpec := clabernetesRunSpec{
		TaskID:             task.ID,
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
	return s.withTaskStep(ctx, task.ID, "clabernetes."+action, func() error {
		return s.runClabernetesTask(ctx, runSpec, log)
	})
}

type terraformTaskSpec struct {
	Action         string         `json:"action,omitempty"` // plan/apply/destroy
	Cloud          string         `json:"cloud,omitempty"`
	TemplateSource string         `json:"templateSource,omitempty"`
	TemplateRepo   string         `json:"templateRepo,omitempty"`
	TemplatesDir   string         `json:"templatesDir,omitempty"`
	Template       string         `json:"template,omitempty"`
	Deployment     string         `json:"deployment,omitempty"`
	DeploymentID   string         `json:"deploymentId,omitempty"`
	Environment    map[string]any `json:"environment,omitempty"`
}

func (s *Service) dispatchTerraformTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	var specIn terraformTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	pc, err := s.systemWorkspaceContext(ctx, task.WorkspaceID, task.CreatedBy)
	if err != nil {
		return err
	}

	cloud := strings.ToLower(strings.TrimSpace(specIn.Cloud))
	if cloud == "" {
		cloud = "aws"
	}
	action := strings.ToLower(strings.TrimSpace(specIn.Action))
	if action == "" {
		action = "plan"
	}

	region := strings.TrimSpace(pc.workspace.AWSRegion)
	if region == "" {
		region = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	env := map[string]any{
		"TF_IN_AUTOMATION":          "true",
		"AWS_EC2_METADATA_DISABLED": "true",
		"AWS_REGION":                region,
		"AWS_DEFAULT_REGION":        region,
		"AWS_SDK_LOAD_CONFIG":       "0",
		"AWS_PROFILE":               "",
	}
	if s.cfg.Workspaces.ObjectStorageTerraformAccessKey != "" && s.cfg.Workspaces.ObjectStorageTerraformSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = s.cfg.Workspaces.ObjectStorageTerraformAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = s.cfg.Workspaces.ObjectStorageTerraformSecretKey
	}
	if shouldUseAWS(pc.workspace) {
		if strings.TrimSpace(pc.workspace.AWSAuthMethod) == "" {
			pc.workspace.AWSAuthMethod = "sso"
		}
		env["TF_VAR_aws_region"] = region
		if err := populateAWSAuthEnv(ctx, s.cfg, s.db, s.awsStore, pc.workspace, pc.claims.Username, env); err != nil {
			return err
		}
	}
	if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.workspace, env); err != nil {
		return err
	}
	if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.workspace, env); err != nil {
		return err
	}

	// Merge deployment-provided environment if present (variable groups).
	dep, err := s.getLatestDeploymentByType(ctx, pc.workspace.ID, "terraform")
	if err == nil && dep != nil {
		cfgAny, _ := fromJSONMap(dep.Config)
		deploymentEnv, err := s.mergeDeploymentEnvironment(ctx, pc.workspace.ID, cfgAny)
		if err == nil {
			for k, v := range deploymentEnv {
				env[k] = v
			}
		}
	}

	// Merge request-provided environment (stored in task spec).
	for k, v := range specIn.Environment {
		env[k] = v
	}

	runSpec := terraformRunSpec{
		TaskID:         task.ID,
		WorkspaceCtx:   pc,
		WorkspaceSlug:  pc.workspace.Slug,
		Username:       pc.claims.Username,
		Cloud:          cloud,
		Action:         action,
		TemplateSource: strings.TrimSpace(specIn.TemplateSource),
		TemplateRepo:   strings.TrimSpace(specIn.TemplateRepo),
		TemplatesDir:   strings.TrimSpace(specIn.TemplatesDir),
		Template:       strings.TrimSpace(specIn.Template),
		Environment:    env,
	}
	action = strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return s.withTaskStep(ctx, task.ID, "terraform."+action, func() error {
		return s.runTerraformTask(ctx, runSpec, log)
	})
}

func (s *Service) dispatchTask(ctx context.Context, task *TaskRecord, log *taskLogger) error {
	if s == nil || task == nil {
		return fmt.Errorf("service unavailable")
	}
	if log == nil {
		return fmt.Errorf("task logger unavailable")
	}
	typ := strings.TrimSpace(task.TaskType)
	switch {
	case typ == "netlab-run":
		return s.dispatchNetlabTask(ctx, task, log)
	case typ == "netlab-c9s-run":
		return s.dispatchNetlabC9sTask(ctx, task, log)
	case typ == "labpp-run":
		return s.dispatchLabppTask(ctx, task, log)
	case typ == "containerlab-run":
		return s.dispatchContainerlabTask(ctx, task, log)
	case typ == "clabernetes-run":
		return s.dispatchClabernetesTask(ctx, task, log)
	case strings.HasPrefix(typ, "terraform-"):
		return s.dispatchTerraformTask(ctx, task, log)
	default:
		return fmt.Errorf("unknown task type: %s", typ)
	}
}
