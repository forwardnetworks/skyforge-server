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

type ProjectRunResponse struct {
	ProjectID string  `json:"projectId"`
	Task      JSONMap `json:"task"`
	User      string  `json:"user"`
}

type ProjectTofuApplyParams struct {
	Confirm        string `query:"confirm" encore:"optional"`
	Cloud          string `query:"cloud" encore:"optional"`
	Action         string `query:"action" encore:"optional"`
	TemplateSource string `query:"templateSource" encore:"optional"`
	TemplateRepo   string `query:"templateRepo" encore:"optional"`
	TemplatesDir   string `query:"templatesDir" encore:"optional"`
	Template       string `query:"template" encore:"optional"`
}

// RunProjectTofuPlan triggers a tofu plan run for a project.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/tofu-plan
func (s *Service) RunProjectTofuPlan(ctx context.Context, id string) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getLatestDeploymentByType(ctx, pc.project.ID, "tofu")
	if err != nil {
		return nil, err
	}
	if dep == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("no tofu deployment configured").Err()
	}
	region := strings.TrimSpace(pc.project.AWSRegion)
	if region == "" {
		region = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	env := map[string]any{
		"TF_IN_AUTOMATION":          "true",
		"AWS_EC2_METADATA_DISABLED": "true",
		"AWS_SDK_LOAD_CONFIG":       "0",
		"AWS_PROFILE":               "",
	}
	if s.cfg.Projects.ObjectStorageTerraformAccessKey != "" && s.cfg.Projects.ObjectStorageTerraformSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = s.cfg.Projects.ObjectStorageTerraformAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = s.cfg.Projects.ObjectStorageTerraformSecretKey
	}
	if shouldUseAWS(pc.project) {
		if strings.TrimSpace(pc.project.AWSAuthMethod) == "" {
			pc.project.AWSAuthMethod = "sso"
		}
		env["TF_VAR_aws_region"] = region
		if err := populateAWSAuthEnv(ctx, s.cfg, s.db, s.awsStore, pc.project, pc.claims.Username, env); err != nil {
			return nil, err
		}
	}
	if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.project, env); err != nil {
		return nil, err
	}
	if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.project, env); err != nil {
		return nil, err
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
			"project.run.tofu-plan",
			pc.project.ID,
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

	meta, err := toJSONMap(map[string]any{
		"deployment": dep.Name,
		"cloud":      cloud,
		"template":   template,
	})
	if err != nil {
		log.Printf("tofu plan meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.project.ID, &dep.ID, "tofu-plan", fmt.Sprintf("Skyforge tofu plan (%s)", pc.claims.Username), pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	spec := tofuRunSpec{
		ProjectCtx:     pc,
		ProjectSlug:    pc.project.Slug,
		Username:       pc.claims.Username,
		Cloud:          strings.ToLower(strings.TrimSpace(cloud)),
		Action:         "plan",
		TemplateSource: strings.TrimSpace(templateSource),
		TemplateRepo:   strings.TrimSpace(templateRepo),
		TemplatesDir:   strings.TrimSpace(templatesDir),
		Template:       strings.TrimSpace(template),
		Environment:    envMap,
	}
	s.queueTask(task, func(ctx context.Context, log *taskLogger) error {
		return s.runTofuTask(ctx, spec, log)
	})

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("tofu plan task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.ID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectTofuApply triggers a tofu apply run for a project.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/tofu-apply
func (s *Service) RunProjectTofuApply(ctx context.Context, id string, params *ProjectTofuApplyParams) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	region := strings.TrimSpace(pc.project.AWSRegion)
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
	if s.cfg.Projects.ObjectStorageTerraformAccessKey != "" && s.cfg.Projects.ObjectStorageTerraformSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = s.cfg.Projects.ObjectStorageTerraformAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = s.cfg.Projects.ObjectStorageTerraformSecretKey
	}
	if cloud == "aws" && shouldUseAWS(pc.project) {
		if strings.TrimSpace(pc.project.AWSAuthMethod) == "" {
			pc.project.AWSAuthMethod = "sso"
		}
		env["TF_VAR_aws_region"] = region
		if err := populateAWSAuthEnv(ctx, s.cfg, s.db, s.awsStore, pc.project, pc.claims.Username, env); err != nil {
			return nil, err
		}
	}
	if cloud == "azure" {
		if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.project, env); err != nil {
			return nil, err
		}
	}
	if cloud == "gcp" {
		if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.project, env); err != nil {
			return nil, err
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
			"project.run.tofu-apply",
			pc.project.ID,
			fmt.Sprintf("action=%s cloud=%s template=%s", action, cloud, templateName),
		)
	}
	meta, err := toJSONMap(map[string]any{
		"cloud":    cloud,
		"template": templateName,
		"action":   action,
	})
	if err != nil {
		log.Printf("tofu apply meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.project.ID, nil, fmt.Sprintf("tofu-%s", action), fmt.Sprintf("Skyforge tofu %s %s (%s)", action, strings.ToUpper(cloud), pc.claims.Username), pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	spec := tofuRunSpec{
		ProjectCtx:     pc,
		ProjectSlug:    pc.project.Slug,
		Username:       pc.claims.Username,
		Cloud:          strings.ToLower(strings.TrimSpace(cloud)),
		Action:         action,
		TemplateSource: templateSource,
		TemplateRepo:   templateRepo,
		TemplatesDir:   templatesDir,
		Template:       templateName,
		Environment:    envMap,
	}
	s.queueTask(task, func(ctx context.Context, log *taskLogger) error {
		return s.runTofuTask(ctx, spec, log)
	})

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("tofu apply task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.ID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectAnsible triggers an ansible run for a project.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/ansible-run
func (s *Service) RunProjectAnsible(ctx context.Context, id string) (*ProjectRunResponse, error) {
	_ = ctx
	_ = id
	return nil, errs.B().Code(errs.Unimplemented).Msg("ansible runs are not supported in native mode").Err()
}

type ProjectNetlabRunRequest struct {
	Message          string  `json:"message,omitempty"`
	GitBranch        string  `json:"gitBranch,omitempty"`
	Environment      JSONMap `json:"environment,omitempty"`
	Action           string  `json:"action,omitempty"`  // up, create, restart, collect, status, down
	Cleanup          bool    `json:"cleanup,omitempty"` // for down/restart, remove workdir when true
	NetlabServer     string  `json:"netlabServer,omitempty"`
	NetlabPassword   string  `json:"netlabPassword,omitempty"`
	NetlabProjectDir string  `json:"netlabProjectDir,omitempty"`
	NetlabMultilabID string  `json:"netlabMultilabId,omitempty"`
	NetlabDeployment string  `json:"netlabDeployment,omitempty"`
	TemplateSource   string  `json:"templateSource,omitempty"` // project (default), blueprints, or custom
	TemplateRepo     string  `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir     string  `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/netlab)
	Template         string  `json:"template,omitempty"`       // filename (e.g. spine-leaf.yml)
}

type ProjectLabppRunRequest struct {
	Message           string  `json:"message,omitempty"`
	GitBranch         string  `json:"gitBranch,omitempty"`
	Environment       JSONMap `json:"environment,omitempty"`
	Action            string  `json:"action,omitempty"` // e2e, upload, start, stop, delete, configure
	EveServer         string  `json:"eveServer,omitempty"`
	TemplatesRoot     string  `json:"templatesRoot,omitempty"`
	Template          string  `json:"template,omitempty"`
	TemplateSource    string  `json:"templateSource,omitempty"`    // project (default), blueprints, or custom
	TemplateRepo      string  `json:"templateRepo,omitempty"`      // owner/repo or URL (custom only)
	TemplatesDir      string  `json:"templatesDir,omitempty"`      // repo-relative directory (default: blueprints/labpp)
	TemplatesDestRoot string  `json:"templatesDestRoot,omitempty"` // host path for synced templates (default: /var/lib/skyforge/labpp-templates)
	LabPath           string  `json:"labPath,omitempty"`
	ThreadCount       int     `json:"threadCount,omitempty"`
	Deployment        string  `json:"deployment,omitempty"`
}

type ProjectContainerlabRunRequest struct {
	Message        string  `json:"message,omitempty"`
	GitBranch      string  `json:"gitBranch,omitempty"`
	Environment    JSONMap `json:"environment,omitempty"`
	Action         string  `json:"action,omitempty"` // deploy, destroy
	NetlabServer   string  `json:"netlabServer,omitempty"`
	TemplateSource string  `json:"templateSource,omitempty"` // project (default), blueprints, or custom
	TemplateRepo   string  `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir   string  `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/containerlab)
	Template       string  `json:"template,omitempty"`       // filename (e.g. lab.yml)
	Deployment     string  `json:"deployment,omitempty"`     // deployment name for lab naming
	Reconfigure    bool    `json:"reconfigure,omitempty"`
}

// RunProjectNetlab triggers a netlab run for a project.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/netlab-run
func (s *Service) RunProjectNetlab(ctx context.Context, id string, req *ProjectNetlabRunRequest) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
		req = &ProjectNetlabRunRequest{}
	}
	serverName := strings.TrimSpace(req.NetlabServer)
	if serverName == "" {
		serverName = strings.TrimSpace(pc.project.NetlabServer)
	}
	if serverName == "" {
		// Netlab runs default to the same server pool as EVE-NG when a dedicated Netlab pool isn't configured.
		serverName = strings.TrimSpace(pc.project.EveServer)
	}
	server, _ := resolveNetlabServer(s.cfg, serverName)
	if server == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab runner is not configured").Err()
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "up"
	}
	switch action {
	case "up", "create", "restart", "collect", "status", "down":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid netlab action (use up, create, restart, collect, status, down)").Err()
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
	projectDir := strings.TrimSpace(req.NetlabProjectDir)
	if projectDir == "" {
		projectDir = fmt.Sprintf("%s/%s/%s", workspaceRoot, strings.TrimSpace(pc.project.Slug), deploymentName)
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
			"project.run.netlab",
			pc.project.ID,
			fmt.Sprintf("action=%s server=%s", action, server.Name),
		)
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	meta, err := toJSONMap(map[string]any{
		"action":     action,
		"server":     server.Name,
		"deployment": deploymentName,
	})
	if err != nil {
		log.Printf("netlab meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.project.ID, nil, "netlab-run", message, pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	spec := netlabRunSpec{
		ProjectCtx:      pc,
		ProjectSlug:     pc.project.Slug,
		Username:        strings.TrimSpace(pc.claims.Username),
		Action:          action,
		Deployment:      deploymentName,
		WorkspaceRoot:   workspaceRoot,
		TemplateSource:  strings.TrimSpace(req.TemplateSource),
		TemplateRepo:    strings.TrimSpace(req.TemplateRepo),
		TemplatesDir:    strings.TrimSpace(req.TemplatesDir),
		Template:        strings.TrimSpace(req.Template),
		ProjectDir:      projectDir,
		MultilabNumeric: multilabNumericID,
		StateRoot:       strings.TrimSpace(server.StateRoot),
		Cleanup:         req.Cleanup,
		Server:          *server,
	}
	s.queueTask(task, func(ctx context.Context, log *taskLogger) error {
		return s.runNetlabTask(ctx, spec, log)
	})

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("netlab task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.ID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectLabpp triggers a LabPP run for a project.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/labpp-run
func (s *Service) RunProjectLabpp(ctx context.Context, id string, req *ProjectLabppRunRequest) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
		req = &ProjectLabppRunRequest{}
	}

	serverName := strings.TrimSpace(req.EveServer)
	if serverName == "" {
		serverName = strings.TrimSpace(pc.project.EveServer)
	}
	var eveServer *EveServerConfig
	if serverName != "" {
		eveServer = eveServerByName(s.cfg.EveServers, serverName)
	}
	if eveServer == nil && len(s.cfg.EveServers) > 0 {
		eveServer = &s.cfg.EveServers[0]
	}
	if eveServer == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("eve server is not configured").Err()
	}

	apiURL := strings.TrimRight(strings.TrimSpace(s.cfg.LabppAPIURL), "/")
	if apiURL == "" {
		base := strings.TrimRight(strings.TrimSpace(eveServer.WebURL), "/")
		if base == "" {
			base = strings.TrimRight(strings.TrimSpace(eveServer.APIURL), "/")
		}
		if base == "" && strings.TrimSpace(eveServer.SSHHost) != "" {
			base = "https://" + strings.TrimSpace(eveServer.SSHHost)
		}
		apiURL = strings.TrimRight(base, "/") + "/labpp"
	}
	apiInsecure := s.cfg.LabppSkipTLSVerify || eveServer.SkipTLSVerify

	eveURL := strings.TrimSpace(eveServer.WebURL)
	if eveURL == "" {
		eveURL = strings.TrimSpace(eveServer.APIURL)
	}
	eveUsername := strings.TrimSpace(eveServer.Username)
	if eveUsername == "" {
		eveUsername = strings.TrimSpace(s.cfg.Labs.EveUsername)
	}
	evePassword := strings.TrimSpace(eveServer.Password)
	if evePassword == "" {
		evePassword = strings.TrimSpace(s.cfg.Labs.EvePassword)
	}
	if strings.TrimSpace(eveURL) == "" || strings.TrimSpace(eveUsername) == "" || evePassword == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve credentials are required for labpp (url/username/password)").Err()
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "e2e"
	}
	switch action {
	case "e2e", "upload", "start", "stop", "delete", "configure":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid labpp action").Err()
	}

	// The LabPP API uses this to parallelize per-node setup/configuration.
	// Default to 1 to reduce load and avoid brittle console races on slower labs.
	threadCount := req.ThreadCount
	if threadCount <= 0 && (action == "e2e" || action == "start" || action == "configure") {
		threadCount = 1
	}

	deployment := strings.TrimSpace(req.Deployment)
	if deployment == "" {
		deployment = strings.TrimSpace(pc.project.Slug)
	}
	templatesRoot := strings.TrimSpace(req.TemplatesRoot)
	template := strings.TrimSpace(req.Template)
	if template == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}
	if templatesRoot == "" {
		destRoot := strings.TrimSpace(req.TemplatesDestRoot)
		source := strings.TrimSpace(req.TemplateSource)
		repo := strings.TrimSpace(req.TemplateRepo)
		dir := strings.TrimSpace(req.TemplatesDir)
		if source == "" {
			source = "project"
		}
		syncedRoot, err := s.syncLabppTemplateDir(ctx, pc, eveServer, source, repo, dir, template, destRoot)
		if err != nil {
			log.Printf("labpp template sync: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync labpp template").Err()
		}
		templatesRoot = strings.TrimSpace(syncedRoot)
	}
	labPath := strings.TrimSpace(req.LabPath)
	if labPath == "" {
		// Keep LabPP labs in a deterministic, per-deployment folder to avoid collisions
		// when the same template is used multiple times.
		// Note: the LabPP API decides the final lab filename; we still include the template
		// in the path so "folder + filename" stays unique and predictable across actions.
		//
		// The LabPP API normalizes the lab filename (e.g. replacing '-' with '_'), so
		// match that behavior to keep Skyforge's EVE-NG links stable.
		labPath = fmt.Sprintf(
			"/Users/%s/%s/%s/%s.unl",
			pc.claims.Username,
			pc.project.Slug,
			deployment,
			labppLabFilename(template),
		)
	}
	if labPath != "" {
		labPath = "/" + strings.TrimPrefix(labPath, "/")
	}

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
			"project.run.labpp",
			pc.project.ID,
			fmt.Sprintf("action=%s server=%s", action, eveServer.Name),
		)
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	meta, err := toJSONMap(map[string]any{
		"action":     action,
		"server":     eveServer.Name,
		"deployment": deployment,
		"template":   template,
	})
	if err != nil {
		log.Printf("labpp meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.project.ID, nil, "labpp-run", message, pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	spec := labppRunSpec{
		APIURL:        apiURL,
		Insecure:      apiInsecure,
		Action:        action,
		ProjectSlug:   strings.TrimSpace(pc.project.Slug),
		Deployment:    deployment,
		TemplatesRoot: templatesRoot,
		Template:      template,
		LabPath:       labPath,
		ThreadCount:   threadCount,
		EveURL:        eveURL,
		EveUsername:   eveUsername,
		EvePassword:   evePassword,
		MaxSeconds:    1200,
	}
	s.queueTask(task, func(ctx context.Context, log *taskLogger) error {
		return s.runLabppTask(ctx, spec, log)
	})

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("labpp task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.ID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectContainerlab triggers a Containerlab run for a project.
//
//encore:api auth method=POST path=/api/workspaces/:id/runs/containerlab-run
func (s *Service) RunProjectContainerlab(ctx context.Context, id string, req *ProjectContainerlabRunRequest) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
		req = &ProjectContainerlabRunRequest{}
	}

	serverName := strings.TrimSpace(req.NetlabServer)
	if serverName == "" {
		serverName = strings.TrimSpace(pc.project.NetlabServer)
	}
	if serverName == "" {
		serverName = strings.TrimSpace(pc.project.EveServer)
	}
	server, _ := resolveNetlabServer(s.cfg, serverName)
	if server == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("containerlab runner is not configured").Err()
	}

	apiURL := containerlabAPIURL(s.cfg, *server)
	if apiURL == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("containerlab api url is not configured").Err()
	}
	token, err := containerlabTokenForUser(s.cfg, pc.claims.Username)
	if err != nil {
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
	labName := containerlabLabName(pc.project.Slug, deploymentName)

	var topologyJSON string
	if action == "deploy" {
		templatesDir := strings.TrimSpace(req.TemplatesDir)
		if templatesDir == "" {
			templatesDir = "blueprints/containerlab"
		}
		templatesDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
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
			"project.run.containerlab",
			pc.project.ID,
			fmt.Sprintf("action=%s server=%s", action, server.Name),
		)
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	meta, err := toJSONMap(map[string]any{
		"action":   action,
		"server":   server.Name,
		"labName":  labName,
		"template": template,
	})
	if err != nil {
		log.Printf("containerlab meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	task, err := createTask(ctx, s.db, pc.project.ID, nil, "containerlab-run", message, pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	var topo map[string]any
	if topologyJSON != "" {
		if err := json.Unmarshal([]byte(topologyJSON), &topo); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to decode topology").Err()
		}
	}
	spec := containerlabRunSpec{
		APIURL:      apiURL,
		Token:       token,
		Action:      action,
		LabName:     labName,
		Topology:    topo,
		Reconfigure: reconfigure,
		SkipTLS:     containerlabSkipTLS(s.cfg, *server),
	}
	s.queueTask(task, func(ctx context.Context, log *taskLogger) error {
		return s.runContainerlabTask(ctx, spec, log)
	})

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("containerlab task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.ID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

func populateAWSAuthEnv(ctx context.Context, cfg Config, db *sql.DB, store awsSSOTokenStore, project SkyforgeProject, username string, env map[string]any) error {
	switch strings.ToLower(strings.TrimSpace(project.AWSAuthMethod)) {
	case "sso":
		accountID := strings.TrimSpace(project.AWSAccountID)
		roleName := strings.TrimSpace(project.AWSRoleName)
		if accountID == "" || roleName == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("project is missing awsAccountId/awsRoleName").Err()
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
		rec, err := getProjectAWSStaticCredentials(ctx, db, newSecretBox(cfg.SessionSecret), project.ID)
		if err != nil {
			log.Printf("aws static get: %v", err)
			return errs.B().Code(errs.Unavailable).Msg("aws static credentials unavailable").Err()
		}
		if rec == nil || rec.AccessKeyID == "" || rec.SecretAccessKey == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("aws static credentials are not configured for this project").Err()
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

func shouldUseAWS(project SkyforgeProject) bool {
	authMethod := strings.ToLower(strings.TrimSpace(project.AWSAuthMethod))
	if authMethod == "" {
		authMethod = "sso"
	}
	switch authMethod {
	case "static":
		return true
	case "sso":
		return strings.TrimSpace(project.AWSAccountID) != "" && strings.TrimSpace(project.AWSRoleName) != ""
	default:
		return false
	}
}

func populateAzureAuthEnv(ctx context.Context, cfg Config, db *sql.DB, project SkyforgeProject, env map[string]any) error {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getProjectAzureCredentials(ctx, db, newSecretBox(cfg.SessionSecret), project.ID)
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

func populateGCPAuthEnv(ctx context.Context, cfg Config, db *sql.DB, project SkyforgeProject, env map[string]any) error {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getProjectGCPCredentials(ctx, db, newSecretBox(cfg.SessionSecret), project.ID)
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
