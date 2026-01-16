package skyforge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"path"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/aws/aws-sdk-go-v2/aws"
	"gopkg.in/yaml.v3"
)

type WorkspaceRunResponse struct {
	WorkspaceID string  `json:"workspaceId"`
	Task        JSONMap `json:"task"`
	User        string  `json:"user"`
}

type WorkspaceTerraformApplyParams struct {
	Confirm        string `query:"confirm" encore:"optional"`
	Cloud          string `query:"cloud" encore:"optional"`
	Action         string `query:"action" encore:"optional"`
	TemplateSource string `query:"templateSource" encore:"optional"`
	TemplateRepo   string `query:"templateRepo" encore:"optional"`
	TemplatesDir   string `query:"templatesDir" encore:"optional"`
	Template       string `query:"template" encore:"optional"`
	DeploymentID   string `query:"deployment_id" encore:"optional"`
}

// RunWorkspaceTerraformPlan triggers a terraform plan run for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/terraform-plan
func (s *Service) RunWorkspaceTerraformPlan(ctx context.Context, id string) (*WorkspaceRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getLatestDeploymentByType(ctx, pc.workspace.ID, "terraform")
	if err != nil {
		return nil, err
	}
	if dep == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("no terraform deployment configured").Err()
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
			return nil, err
		}
	}
	if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.workspace, env); err != nil {
		return nil, err
	}
	if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.workspace, env); err != nil {
		return nil, err
	}

	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.run.terraform-plan",
			pc.workspace.ID,
			fmt.Sprintf("deployment=%s", dep.Name),
		)
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	templateSource, _ := cfgAny["templateSource"].(string)
	templateRepo, _ := cfgAny["templateRepo"].(string)
	templatesDir, _ := cfgAny["templatesDir"].(string)
	template, _ := cfgAny["template"].(string)
	cloud, _ := cfgAny["cloud"].(string)
	if strings.TrimSpace(cloud) == "" {
		cloud = "aws"
	}

	deploymentEnv, err := s.mergeDeploymentEnvironment(ctx, pc.workspace.ID, cfgAny)
	if err != nil {
		return nil, err
	}
	for k, v := range deploymentEnv {
		env[k] = v
	}
	envMap := env

	meta, err := toJSONMap(map[string]any{
		"deployment": dep.Name,
		"cloud":      cloud,
		"template":   template,
		"spec": map[string]any{
			"action":         "plan",
			"cloud":          cloud,
			"templateSource": strings.TrimSpace(templateSource),
			"templateRepo":   strings.TrimSpace(templateRepo),
			"templatesDir":   strings.TrimSpace(templatesDir),
			"template":       strings.TrimSpace(template),
			"deployment":     strings.TrimSpace(dep.Name),
			"deploymentId":   strings.TrimSpace(dep.ID),
			"environment":    envMap,
		},
	})
	if err != nil {
		log.Printf("terraform plan meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.workspace.ID, &dep.ID, "terraform-plan", fmt.Sprintf("Skyforge terraform plan (%s)", pc.claims.Username), pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("terraform plan task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}

// RunWorkspaceTerraformApply triggers a terraform apply run for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/terraform-apply
func (s *Service) RunWorkspaceTerraformApply(ctx context.Context, id string, params *WorkspaceTerraformApplyParams) (*WorkspaceRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	confirm := ""
	cloud := "aws"
	action := "apply"
	templateSource := ""
	templateRepo := ""
	templatesDir := ""
	templateName := ""
	deploymentID := ""
	if params != nil {
		confirm = strings.TrimSpace(params.Confirm)
		if raw := strings.TrimSpace(params.Cloud); raw != "" {
			cloud = strings.ToLower(raw)
		}
		if raw := strings.TrimSpace(params.Action); raw != "" {
			action = strings.ToLower(raw)
		}
		if raw := strings.TrimSpace(params.TemplateSource); raw != "" {
			templateSource = strings.ToLower(raw)
		}
		templateRepo = strings.TrimSpace(params.TemplateRepo)
		templatesDir = strings.TrimSpace(params.TemplatesDir)
		templateName = strings.TrimSpace(params.Template)
		deploymentID = strings.TrimSpace(params.DeploymentID)
	}
	if !strings.EqualFold(confirm, "true") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("apply requires ?confirm=true").Err()
	}
	if action != "apply" && action != "destroy" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid action (use apply or destroy)").Err()
	}
	if templateName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}
	switch cloud {
	case "aws", "azure", "gcp":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown cloud").Err()
	}
	region := strings.TrimSpace(pc.workspace.AWSRegion)
	if region == "" {
		region = "us-east-1"
	}
	env := map[string]any{
		"TF_IN_AUTOMATION":          "true",
		"AWS_EC2_METADATA_DISABLED": "true",
		"AWS_SDK_LOAD_CONFIG":       "0",
		"AWS_PROFILE":               "",
	}
	if templateName != "" {
		if templatesDir == "" {
			templatesDir = fmt.Sprintf("cloud/terraform/%s", cloud)
		}
		templatesDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		templateName = strings.Trim(strings.TrimSpace(templateName), "/")
		templatePath := path.Join(templatesDir, templateName)
		if !isSafeRelativePath(templatePath) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a safe repo-relative path").Err()
		}
	}
	if s.cfg.Workspaces.ObjectStorageTerraformAccessKey != "" && s.cfg.Workspaces.ObjectStorageTerraformSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = s.cfg.Workspaces.ObjectStorageTerraformAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = s.cfg.Workspaces.ObjectStorageTerraformSecretKey
	}
	if cloud == "aws" && shouldUseAWS(pc.workspace) {
		if strings.TrimSpace(pc.workspace.AWSAuthMethod) == "" {
			pc.workspace.AWSAuthMethod = "sso"
		}
		env["TF_VAR_aws_region"] = region
		if err := populateAWSAuthEnv(ctx, s.cfg, s.db, s.awsStore, pc.workspace, pc.claims.Username, env); err != nil {
			return nil, err
		}
	}
	if cloud == "azure" {
		if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.workspace, env); err != nil {
			return nil, err
		}
	}
	if cloud == "gcp" {
		if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.workspace, env); err != nil {
			return nil, err
		}
	}

	if deploymentID != "" {
		dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
		if err != nil {
			return nil, err
		}
		cfgAny, _ := fromJSONMap(dep.Config)
		deploymentEnv, err := s.mergeDeploymentEnvironment(ctx, pc.workspace.ID, cfgAny)
		if err != nil {
			return nil, err
		}
		for k, v := range deploymentEnv {
			env[k] = v
		}
	}

	envMap := env
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.run.terraform-apply",
			pc.workspace.ID,
			fmt.Sprintf("action=%s cloud=%s template=%s", action, cloud, templateName),
		)
	}
	meta, err := toJSONMap(map[string]any{
		"cloud":    cloud,
		"template": templateName,
		"action":   action,
		"spec": map[string]any{
			"action":         action,
			"cloud":          cloud,
			"templateSource": strings.TrimSpace(templateSource),
			"templateRepo":   strings.TrimSpace(templateRepo),
			"templatesDir":   strings.TrimSpace(templatesDir),
			"template":       strings.TrimSpace(templateName),
			"environment":    envMap,
		},
	})
	if err != nil {
		log.Printf("terraform apply meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.workspace.ID, nil, fmt.Sprintf("terraform-%s", action), fmt.Sprintf("Skyforge terraform %s %s (%s)", action, strings.ToUpper(cloud), pc.claims.Username), pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("terraform apply task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}

// RunWorkspaceAnsible triggers an ansible run for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/ansible-run
func (s *Service) RunWorkspaceAnsible(ctx context.Context, id string) (*WorkspaceRunResponse, error) {
	_ = ctx
	_ = id
	return nil, errs.B().Code(errs.Unimplemented).Msg("ansible runs are not supported in native mode").Err()
}

type WorkspaceNetlabRunRequest struct {
	Message            string  `json:"message,omitempty"`
	GitBranch          string  `json:"gitBranch,omitempty"`
	Environment        JSONMap `json:"environment,omitempty"`
	Action             string  `json:"action,omitempty"`  // up, create, restart, collect, status, down, clab-tarball
	Cleanup            bool    `json:"cleanup,omitempty"` // for down/restart, remove workdir when true
	NetlabServer       string  `json:"netlabServer,omitempty"`
	NetlabPassword     string  `json:"netlabPassword,omitempty"`
	NetlabWorkspaceDir string  `json:"netlabWorkspaceDir,omitempty"`
	NetlabMultilabID   string  `json:"netlabMultilabId,omitempty"`
	NetlabDeployment   string  `json:"netlabDeployment,omitempty"`
	TemplateSource     string  `json:"templateSource,omitempty"` // workspace (default), blueprints, or custom
	TemplateRepo       string  `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir       string  `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/netlab)
	Template           string  `json:"template,omitempty"`       // filename (e.g. spine-leaf.yml)
	ClabTarball        string  `json:"clabTarball,omitempty"`
	ClabConfigDir      string  `json:"clabConfigDir,omitempty"`
	ClabCleanup        bool    `json:"clabCleanup,omitempty"`
}

type WorkspaceLabppRunRequest struct {
	Message           string  `json:"message,omitempty"`
	GitBranch         string  `json:"gitBranch,omitempty"`
	Environment       JSONMap `json:"environment,omitempty"`
	Action            string  `json:"action,omitempty"` // e2e, upload, start, stop, delete, configure
	EveServer         string  `json:"eveServer,omitempty"`
	EveUsername       string  `json:"eveUsername,omitempty"`
	EvePassword       string  `json:"evePassword,omitempty"`
	TemplatesRoot     string  `json:"templatesRoot,omitempty"`
	Template          string  `json:"template,omitempty"`
	TemplateSource    string  `json:"templateSource,omitempty"`    // workspace (default), blueprints, or custom
	TemplateRepo      string  `json:"templateRepo,omitempty"`      // owner/repo or URL (custom only)
	TemplatesDir      string  `json:"templatesDir,omitempty"`      // repo-relative directory (default: blueprints/labpp)
	TemplatesDestRoot string  `json:"templatesDestRoot,omitempty"` // host path for synced templates (default: /var/lib/skyforge/labpp/templates)
	LabPath           string  `json:"labPath,omitempty"`
	ThreadCount       int     `json:"threadCount,omitempty"`
	Deployment        string  `json:"deployment,omitempty"`
	DeploymentID      string  `json:"deploymentId,omitempty"`
}

type WorkspaceContainerlabRunRequest struct {
	Message        string  `json:"message,omitempty"`
	GitBranch      string  `json:"gitBranch,omitempty"`
	Environment    JSONMap `json:"environment,omitempty"`
	Action         string  `json:"action,omitempty"` // deploy, destroy
	NetlabServer   string  `json:"netlabServer,omitempty"`
	TemplateSource string  `json:"templateSource,omitempty"` // workspace (default), blueprints, or custom
	TemplateRepo   string  `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir   string  `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/containerlab)
	Template       string  `json:"template,omitempty"`       // filename (e.g. lab.yml)
	Deployment     string  `json:"deployment,omitempty"`     // deployment name for lab naming
	Reconfigure    bool    `json:"reconfigure,omitempty"`
}

// RunWorkspaceNetlab triggers a netlab run for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/netlab-run
func (s *Service) RunWorkspaceNetlab(ctx context.Context, id string, req *WorkspaceNetlabRunRequest) (*WorkspaceRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		req = &WorkspaceNetlabRunRequest{}
	}
	serverRef := strings.TrimSpace(req.NetlabServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if serverRef == "" {
		// Back-compat for older workspaces that used EveServer as the default runner pool.
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, serverRef)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "up"
	}
	switch action {
	case "up", "create", "restart", "collect", "status", "down", "clab-tarball":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid netlab action (use up, create, restart, collect, status, down, clab-tarball)").Err()
	}

	multilabID := strings.TrimSpace(req.NetlabMultilabID)
	if multilabID == "" {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err == nil {
			multilabID = hex.EncodeToString(buf)
		} else {
			multilabID = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
	}

	// Netlab multilab plugin requires an integer defaults.multilab.id. Derive a stable uint32 from the
	// deployment/run id, and cap it to a small range to avoid port collisions and to satisfy multilab
	// validation (defaults.multilab.id must be an integer < 200).
	h := fnv.New32a()
	_, _ = h.Write([]byte(multilabID))
	// Range 1..199 (multilab rejects 0 and values >= 200).
	multilabNumericID := int(h.Sum32()%199) + 1

	deploymentName := strings.TrimSpace(req.NetlabDeployment)
	if deploymentName == "" {
		deploymentName = multilabID
	}

	workspaceRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)

	// Backwards-compat for older runner scripts/config.
	workspaceDir := strings.TrimSpace(req.NetlabWorkspaceDir)
	if workspaceDir == "" {
		workspaceDir = fmt.Sprintf("%s/%s/%s", workspaceRoot, strings.TrimSpace(pc.workspace.Slug), deploymentName)
	}
	clabTarball := strings.TrimSpace(req.ClabTarball)
	if action == "clab-tarball" && clabTarball == "" {
		clabTarball = fmt.Sprintf("containerlab-%s.tar.gz", deploymentName)
	}

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge netlab run (%s)", pc.claims.Username)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.run.netlab",
			pc.workspace.ID,
			fmt.Sprintf("action=%s server=%s", action, strings.TrimSpace(server.Name)),
		)
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	envAny, _ := fromJSONMap(req.Environment)
	envMap := parseEnvMap(envAny)
	meta, err := toJSONMap(map[string]any{
		"action":     action,
		"server":     strings.TrimSpace(server.Name),
		"serverRef":  serverRef,
		"deployment": deploymentName,
		"priority":   taskPriorityInteractive,
		"dedupeKey":  fmt.Sprintf("netlab:%s:%s:%s", pc.workspace.ID, action, deploymentName),
		"spec": map[string]any{
			"action":          action,
			"server":          serverRef,
			"serverLabel":     strings.TrimSpace(server.Name),
			"deployment":      deploymentName,
			"deploymentId":    strings.TrimSpace(req.NetlabMultilabID),
			"workspaceRoot":   workspaceRoot,
			"templateSource":  strings.TrimSpace(req.TemplateSource),
			"templateRepo":    strings.TrimSpace(req.TemplateRepo),
			"templatesDir":    strings.TrimSpace(req.TemplatesDir),
			"template":        strings.TrimSpace(req.Template),
			"workspaceDir":    strings.TrimSpace(workspaceDir),
			"multilabNumeric": multilabNumericID,
			"cleanup":         req.Cleanup,
			"clabTarball":     clabTarball,
			"clabConfigDir":   strings.TrimSpace(req.ClabConfigDir),
			"clabCleanup":     req.ClabCleanup,
			"environment":     envMap,
		},
	})
	if err != nil {
		log.Printf("netlab meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	allowActive := action == "down"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.workspace.ID, nil, "netlab-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.workspace.ID, nil, "netlab-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("netlab task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}

// RunWorkspaceLabpp triggers a LabPP run for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/labpp-run
func (s *Service) RunWorkspaceLabpp(ctx context.Context, id string, req *WorkspaceLabppRunRequest) (*WorkspaceRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		req = &WorkspaceLabppRunRequest{}
	}
	if strings.TrimSpace(s.cfg.LabppConfigDirBase) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("labpp config dir base is not configured").Err()
	}
	if err := ensureWritableDir(strings.TrimSpace(s.cfg.LabppConfigDirBase)); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("labpp config dir base is not writable").Err()
	}

	serverRef := strings.TrimSpace(req.EveServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	resolvedEve, err := s.resolveWorkspaceEveServerConfig(ctx, pc.workspace.ID, serverRef)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}
	eveServer := &resolvedEve.Server

	eveURL := strings.TrimSpace(eveServer.WebURL)
	if eveURL == "" {
		eveURL = strings.TrimSpace(eveServer.APIURL)
	}
	eveUsername := strings.TrimSpace(req.EveUsername)
	evePassword := strings.TrimSpace(req.EvePassword)
	if eveUsername == "" {
		eveUsername = strings.TrimSpace(pc.claims.Username)
	}
	if evePassword == "" {
		cached, ok := getCachedLDAPPassword(s.db, pc.claims.Username)
		if ok {
			evePassword = strings.TrimSpace(cached)
		}
	}
	if strings.TrimSpace(eveUsername) == "" || strings.TrimSpace(evePassword) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve credentials are required for labpp (username/password)").Err()
	}
	if strings.TrimSpace(eveURL) == "" || eveUsername == "" || strings.TrimSpace(evePassword) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve credentials are required for labpp (url/username/password)").Err()
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "e2e"
	}
	switch action {
	case "e2e", "upload", "start", "stop", "delete", "configure", "config":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid labpp action").Err()
	}

	needsDataDir := action != "stop" && action != "delete"
	if needsDataDir {
		platformDataDir := strings.TrimSpace(s.cfg.PlatformDataDir)
		if platformDataDir == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("platform data dir is not configured").Err()
		}
		if err := ensureWritableDir(platformDataDir); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("platform data dir is not writable").Err()
		}
	}

	// The LabPP API uses this to parallelize per-node setup/configuration.
	threadCount := req.ThreadCount

	deployment := strings.TrimSpace(req.Deployment)
	if deployment == "" {
		deployment = strings.TrimSpace(pc.workspace.Slug)
	}
	templatesRoot := strings.TrimSpace(req.TemplatesRoot)
	template := strings.TrimSpace(req.Template)
	if template == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}
	destRoot := strings.TrimSpace(req.TemplatesDestRoot)
	if destRoot == "" {
		destRoot = templatesRoot
	}
	source := strings.TrimSpace(req.TemplateSource)
	repo := strings.TrimSpace(req.TemplateRepo)
	dir := strings.TrimSpace(req.TemplatesDir)
	if source == "" {
		source = "blueprints"
	}
	syncedRoot, err := s.syncLabppTemplateDir(ctx, pc, eveServer, source, repo, dir, template, destRoot)
	if err != nil {
		log.Printf("labpp template sync: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync labpp template").Err()
	}
	templatesRoot = strings.TrimSpace(syncedRoot)
	labPath := strings.TrimSpace(req.LabPath)
	if labPath == "" && strings.TrimSpace(req.DeploymentID) != "" {
		if dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, strings.TrimSpace(req.DeploymentID)); err == nil && dep != nil {
			if raw, ok := dep.Config["labPath"]; ok {
				var v string
				if err := json.Unmarshal(raw, &v); err == nil {
					labPath = strings.TrimSpace(v)
				}
			}
		}
	}
	if labPath == "" {
		labPath = labppLabPath(pc.claims.Username, deployment, template, time.Now())
	}
	labPath = labppNormalizeFolderPath(labPath)
	log.Printf("labpp run config: template=%s templatesRoot=%s labPath=%s action=%s", template, templatesRoot, labPath, action)

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge labpp run (%s)", pc.claims.Username)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.run.labpp",
			pc.workspace.ID,
			fmt.Sprintf("action=%s server=%s", action, strings.TrimSpace(eveServer.Name)),
		)
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	envAny, _ := fromJSONMap(req.Environment)
	envMap := parseEnvMap(envAny)
	evePasswordEnc := ""
	// Under OIDC there is no LDAP password to reuse for EVE; the user supplies an
	// EVE password at run-time. Never store plaintext passwords in task metadata.
	if strings.TrimSpace(req.EvePassword) != "" {
		evePasswordEnc = encryptUserSecret(strings.TrimSpace(req.EvePassword))
	}
	meta, err := toJSONMap(map[string]any{
		"action":     action,
		"server":     strings.TrimSpace(eveServer.Name),
		"serverRef":  serverRef,
		"deployment": deployment,
		"template":   template,
		"priority":   taskPriorityInteractive,
		"dedupeKey":  fmt.Sprintf("labpp:%s:%s:%s:%s", pc.workspace.ID, strings.TrimSpace(req.DeploymentID), action, template),
		"spec": map[string]any{
			"action":            action,
			"eveServer":         serverRef,
			"eveServerLabel":    strings.TrimSpace(eveServer.Name),
			"eveUrl":            eveURL,
			"eveUsername":       eveUsername,
			"evePasswordEnc":    evePasswordEnc,
			"deployment":        deployment,
			"deploymentId":      strings.TrimSpace(req.DeploymentID),
			"templatesRoot":     templatesRoot,
			"template":          template,
			"labPath":           labPath,
			"threadCount":       threadCount,
			"maxSeconds":        1200,
			"environment":       envMap,
			"templateSource":    source,
			"templateRepo":      repo,
			"templatesDir":      dir,
			"templatesDestRoot": destRoot,
		},
	})
	if err != nil {
		log.Printf("labpp meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	deploymentID := strings.TrimSpace(req.DeploymentID)
	allowActive := action == "stop" || action == "delete"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.workspace.ID, &deploymentID, "labpp-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.workspace.ID, &deploymentID, "labpp-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("labpp task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}

// RunWorkspaceContainerlab triggers a Containerlab run for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/containerlab-run
func (s *Service) RunWorkspaceContainerlab(ctx context.Context, id string, req *WorkspaceContainerlabRunRequest) (*WorkspaceRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		req = &WorkspaceContainerlabRunRequest{}
	}

	serverRef := strings.TrimSpace(req.NetlabServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, serverRef)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	if containerlabAPIURL(s.cfg, *server) == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("containerlab api url is not configured").Err()
	}
	if _, err := containerlabTokenForUser(s.cfg, pc.claims.Username); err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab jwt secret is not configured").Err()
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	reconfigure := req.Reconfigure
	switch action {
	case "", "deploy", "create", "start", "up":
		if action == "start" {
			reconfigure = true
		}
		action = "deploy"
	case "destroy", "delete", "down", "stop":
		action = "destroy"
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid containerlab action (use deploy or destroy)").Err()
	}

	template := strings.TrimSpace(req.Template)
	if action == "deploy" && template == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab template is required").Err()
	}

	deploymentName := strings.TrimSpace(req.Deployment)
	if deploymentName == "" {
		deploymentName = strings.TrimSpace(template)
	}
	labName := containerlabLabName(pc.workspace.Slug, deploymentName)

	var topologyJSON string
	if action == "deploy" {
		templatesDir := normalizeContainerlabTemplatesDir(req.TemplateSource, req.TemplatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, req.TemplateSource, req.TemplateRepo)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		filePath := path.Join(templatesDir, template)
		body, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, filePath, ref.Branch)
		if err != nil {
			log.Printf("containerlab template read: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to read containerlab template").Err()
		}
		var topo map[string]any
		if err := yaml.Unmarshal(body, &topo); err != nil {
			log.Printf("containerlab template parse: %v", err)
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid containerlab topology").Err()
		}
		if topo == nil {
			topo = map[string]any{}
		}
		topo["name"] = labName
		topologyBytes, err := json.Marshal(topo)
		if err != nil {
			log.Printf("containerlab template encode: %v", err)
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode topology").Err()
		}
		topologyJSON = string(topologyBytes)
	}

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge containerlab run (%s)", pc.claims.Username)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.run.containerlab",
			pc.workspace.ID,
			fmt.Sprintf("action=%s server=%s", action, strings.TrimSpace(server.Name)),
		)
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	envAny, _ := fromJSONMap(req.Environment)
	envMap := parseEnvMap(envAny)
	meta, err := toJSONMap(map[string]any{
		"action":    action,
		"server":    strings.TrimSpace(server.Name),
		"serverRef": serverRef,
		"labName":   labName,
		"template":  template,
		"priority":  taskPriorityInteractive,
		"dedupeKey": fmt.Sprintf("containerlab:%s:%s:%s", pc.workspace.ID, action, labName),
		"spec": map[string]any{
			"action":       action,
			"netlabServer": serverRef,
			"serverLabel":  strings.TrimSpace(server.Name),
			"deployment":   deploymentName,
			"labName":      labName,
			"reconfigure":  reconfigure,
			"topologyJSON": topologyJSON,
			"environment":  envMap,
		},
	})
	if err != nil {
		log.Printf("containerlab meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	allowActive := action == "destroy"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.workspace.ID, nil, "containerlab-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.workspace.ID, nil, "containerlab-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}
	if topologyJSON != "" {
		var topo map[string]any
		if err := json.Unmarshal([]byte(topologyJSON), &topo); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to decode topology").Err()
		}
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("containerlab task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}

func populateAWSAuthEnv(ctx context.Context, cfg Config, db *sql.DB, store awsSSOTokenStore, workspace SkyforgeWorkspace, username string, env map[string]any) error {
	switch strings.ToLower(strings.TrimSpace(workspace.AWSAuthMethod)) {
	case "sso":
		accountID := strings.TrimSpace(workspace.AWSAccountID)
		roleName := strings.TrimSpace(workspace.AWSRoleName)
		if accountID == "" || roleName == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("workspace is missing awsAccountId/awsRoleName").Err()
		}
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		creds, err := getAWSRoleCredentials(ctx, cfg, store, username, accountID, roleName)
		if err != nil {
			log.Printf("aws sso role creds: %v", err)
			return errs.B().Code(errs.Unavailable).Msg("aws sso credentials unavailable").Err()
		}
		roleCreds := creds.RoleCredentials
		if roleCreds == nil || roleCreds.AccessKeyId == nil || roleCreds.SecretAccessKey == nil || roleCreds.SessionToken == nil {
			return errs.B().Code(errs.Unavailable).Msg("aws sso credentials unavailable").Err()
		}
		accessKeyID := aws.ToString(roleCreds.AccessKeyId)
		secretAccessKey := aws.ToString(roleCreds.SecretAccessKey)
		sessionToken := aws.ToString(roleCreds.SessionToken)
		env["AWS_ACCESS_KEY_ID"] = accessKeyID
		env["AWS_SECRET_ACCESS_KEY"] = secretAccessKey
		env["AWS_SESSION_TOKEN"] = sessionToken
		env["TF_VAR_aws_access_key_id"] = accessKeyID
		env["TF_VAR_aws_secret_access_key"] = secretAccessKey
		env["TF_VAR_aws_session_token"] = sessionToken
	case "static":
		if db == nil {
			return errs.B().Code(errs.Unavailable).Msg("aws static credentials unavailable (db not configured)").Err()
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		rec, err := getWorkspaceAWSStaticCredentials(ctx, db, newSecretBox(cfg.SessionSecret), workspace.ID)
		if err != nil {
			log.Printf("aws static get: %v", err)
			return errs.B().Code(errs.Unavailable).Msg("aws static credentials unavailable").Err()
		}
		if rec == nil || rec.AccessKeyID == "" || rec.SecretAccessKey == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("aws static credentials are not configured for this workspace").Err()
		}
		env["TF_VAR_aws_access_key_id"] = rec.AccessKeyID
		env["TF_VAR_aws_secret_access_key"] = rec.SecretAccessKey
		if rec.SessionToken != "" {
			env["TF_VAR_aws_session_token"] = rec.SessionToken
		}
	default:
		return errs.B().Code(errs.InvalidArgument).Msg("awsAuthMethod must be sso or static").Err()
	}
	return nil
}

func shouldUseAWS(workspace SkyforgeWorkspace) bool {
	authMethod := strings.ToLower(strings.TrimSpace(workspace.AWSAuthMethod))
	if authMethod == "" {
		authMethod = "sso"
	}
	switch authMethod {
	case "static":
		return true
	case "sso":
		return strings.TrimSpace(workspace.AWSAccountID) != "" && strings.TrimSpace(workspace.AWSRoleName) != ""
	default:
		return false
	}
}

func populateAzureAuthEnv(ctx context.Context, cfg Config, db *sql.DB, workspace SkyforgeWorkspace, env map[string]any) error {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getWorkspaceAzureCredentials(ctx, db, newSecretBox(cfg.SessionSecret), workspace.ID)
	if err != nil {
		log.Printf("azure creds get: %v", err)
		return errs.B().Code(errs.Unavailable).Msg("azure credentials unavailable").Err()
	}
	if rec == nil || rec.ClientID == "" || rec.ClientSecret == "" || rec.TenantID == "" || rec.SubscriptionID == "" {
		return nil
	}
	env["ARM_TENANT_ID"] = rec.TenantID
	env["ARM_CLIENT_ID"] = rec.ClientID
	env["ARM_CLIENT_SECRET"] = rec.ClientSecret
	env["ARM_SUBSCRIPTION_ID"] = rec.SubscriptionID
	env["TF_VAR_azure_subscription_id"] = rec.SubscriptionID
	env["TF_VAR_azure_region"] = "eastus"
	return nil
}

func populateGCPAuthEnv(ctx context.Context, cfg Config, db *sql.DB, workspace SkyforgeWorkspace, env map[string]any) error {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getWorkspaceGCPCredentials(ctx, db, newSecretBox(cfg.SessionSecret), workspace.ID)
	if err != nil {
		log.Printf("gcp creds get: %v", err)
		return errs.B().Code(errs.Unavailable).Msg("gcp credentials unavailable").Err()
	}
	if rec == nil || strings.TrimSpace(rec.ServiceAccountJSON) == "" {
		return nil
	}
	projectID := strings.TrimSpace(rec.ProjectIDOverride)
	if projectID == "" {
		payload, parseErr := parseGCPServiceAccountJSON(rec.ServiceAccountJSON)
		if parseErr == nil && payload.ProjectID != "" {
			projectID = payload.ProjectID
		}
	}
	env["GOOGLE_CREDENTIALS"] = rec.ServiceAccountJSON
	if projectID != "" {
		env["TF_VAR_gcp_project"] = projectID
		env["GOOGLE_PROJECT"] = projectID
	}
	env["TF_VAR_gcp_region"] = "us-central1"
	return nil
}
