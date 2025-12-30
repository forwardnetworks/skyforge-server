package skyforge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type ProjectRunResponse struct {
	ProjectID int     `json:"project_id"`
	Task      JSONMap `json:"task"`
	User      string  `json:"user"`
}

type ProjectTofuApplyParams struct {
	Confirm string `query:"confirm" encore:"optional"`
	Cloud   string `query:"cloud" encore:"optional"`
	Action  string `query:"action" encore:"optional"`
}

func semaphoreConfigForUser(cfg Config, username string) (Config, error) {
	password, ok := getCachedLDAPPassword(username)
	if !ok {
		// Fall back to an internal admin account when available.
		// This keeps the UI functional even when the user hasn't reauthenticated
		// after a server restart (LDAP password cache is session-scoped).
		if strings.TrimSpace(cfg.SemaphoreAdminUsername) != "" && strings.TrimSpace(cfg.SemaphoreAdminPassword) != "" {
			cfg.SemaphoreToken = ""
			cfg.SemaphoreUsername = strings.TrimSpace(cfg.SemaphoreAdminUsername)
			cfg.SemaphorePassword = strings.TrimSpace(cfg.SemaphoreAdminPassword)
			cfg.SemaphorePasswordFile = ""
			return cfg, nil
		}
		return cfg, errs.B().Code(errs.FailedPrecondition).Msg("LDAP password unavailable; reauthenticate").Err()
	}
	cfg.SemaphoreToken = ""
	cfg.SemaphoreUsername = username
	cfg.SemaphorePassword = password
	cfg.SemaphorePasswordFile = ""
	return cfg, nil
}

func ensureSemaphoreRepoAccessForUser(cfg Config, project SkyforgeProject, username string) error {
	if project.SemaphoreProjectID == 0 {
		return errs.B().Code(errs.InvalidArgument).Msg("project is missing semaphore wiring").Err()
	}
	if !strings.EqualFold(strings.TrimSpace(project.GiteaOwner), strings.TrimSpace(username)) {
		return nil
	}
	password, ok := getCachedLDAPPassword(username)
	if !ok {
		// Repo access is typically provisioned at project creation time; if the user's LDAP
		// password isn't cached (e.g., server restart), skip the re-provision step and let
		// the run proceed. Semaphore will fail the clone step if access is truly missing.
		return nil
	}
	gitBranch := strings.TrimSpace(project.DefaultBranch)
	if gitBranch == "" {
		gitBranch = "master"
	}
	giteaBase := giteaInternalBaseURL(cfg)
	if giteaBase == "" {
		return errs.B().Code(errs.FailedPrecondition).Msg("gitea base URL not configured").Err()
	}
	gitURL := fmt.Sprintf("%s/%s/%s.git", giteaBase, project.GiteaOwner, project.GiteaRepo)
	keyID, err := ensureSemaphoreHTTPKey(cfg, project.SemaphoreProjectID, "gitea-http", username, password)
	if err != nil {
		return err
	}
	if _, err := ensureSemaphoreRepo(cfg, project.SemaphoreProjectID, project.GiteaRepo, gitURL, gitBranch, keyID); err != nil {
		return err
	}
	return nil
}

// RunProjectTofuPlan triggers a tofu plan run for a project.
//
//encore:api auth method=POST path=/api/projects/:id/runs/tofu-plan
func (s *Service) RunProjectTofuPlan(ctx context.Context, id string) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.project.TofuPlanTemplateID == 0 || pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project is missing tofu plan wiring").Err()
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
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

	runReq := RunRequest{
		TemplateID:  pc.project.TofuPlanTemplateID,
		ProjectID:   &pc.project.SemaphoreProjectID,
		Message:     fmt.Sprintf("Skyforge tofu plan (%s)", pc.claims.Username),
		Environment: nil,
	}
	envJSON, err := toJSONMap(env)
	if err != nil {
		log.Printf("tofu plan env encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode environment").Err()
	}
	runReq.Environment = envJSON
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
			fmt.Sprintf("templateId=%d semaphoreProjectId=%d", pc.project.TofuPlanTemplateID, pc.project.SemaphoreProjectID),
		)
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	if err := ensureSemaphoreRepoAccessForUser(semaphoreCfg, pc.project, pc.claims.Username); err != nil {
		return nil, err
	}
	task, err := startSemaphoreRun(ctx, semaphoreCfg, s.db, pc.claims, runReq)
	if err != nil {
		return nil, err
	}
	taskJSON, err := toJSONMap(task)
	if err != nil {
		log.Printf("tofu plan task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.SemaphoreProjectID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectTofuApply triggers a tofu apply run for a project.
//
//encore:api auth method=POST path=/api/projects/:id/runs/tofu-apply
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
	if pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project is missing tofu apply wiring").Err()
	}
	confirm := ""
	cloud := "aws"
	action := "apply"
	if params != nil {
		confirm = strings.TrimSpace(params.Confirm)
		if raw := strings.TrimSpace(params.Cloud); raw != "" {
			cloud = strings.ToLower(raw)
		}
		if raw := strings.TrimSpace(params.Action); raw != "" {
			action = strings.ToLower(raw)
		}
	}
	if !strings.EqualFold(confirm, "true") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("apply requires ?confirm=true").Err()
	}
	if action != "apply" && action != "destroy" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid action (use apply or destroy)").Err()
	}
	templateID := 0
	switch cloud {
	case "aws":
		templateID = pc.project.TofuInitTemplateID
	case "azure":
		templateID = pc.project.TofuPlanTemplateID
	case "gcp":
		templateID = pc.project.TofuApplyTemplateID
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown cloud").Err()
	}
	if templateID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project is missing tofu apply wiring").Err()
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

	runReq := RunRequest{
		TemplateID:  templateID,
		ProjectID:   &pc.project.SemaphoreProjectID,
		Message:     fmt.Sprintf("Skyforge tofu %s %s (%s)", action, strings.ToUpper(cloud), pc.claims.Username),
		Environment: nil,
	}
	paramsPayload := map[string]any{
		"auto_approve": true,
	}
	if action == "destroy" {
		paramsPayload["destroy"] = true
	}
	extra, err := toJSONMap(map[string]any{
		"params": paramsPayload,
	})
	if err != nil {
		log.Printf("tofu apply params encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode task params").Err()
	}
	runReq.Extra = extra
	envJSON, err := toJSONMap(env)
	if err != nil {
		log.Printf("tofu apply env encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode environment").Err()
	}
	runReq.Environment = envJSON
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
			fmt.Sprintf("templateId=%d semaphoreProjectId=%d action=%s cloud=%s", templateID, pc.project.SemaphoreProjectID, action, cloud),
		)
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	if err := ensureSemaphoreRepoAccessForUser(semaphoreCfg, pc.project, pc.claims.Username); err != nil {
		return nil, err
	}
	task, err := startSemaphoreRun(ctx, semaphoreCfg, s.db, pc.claims, runReq)
	if err != nil {
		return nil, err
	}
	taskJSON, err := toJSONMap(task)
	if err != nil {
		log.Printf("tofu apply task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.SemaphoreProjectID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectAnsible triggers an ansible run for a project.
//
//encore:api auth method=POST path=/api/projects/:id/runs/ansible-run
func (s *Service) RunProjectAnsible(ctx context.Context, id string) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.project.AnsibleRunTemplateID == 0 || pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project is missing ansible run wiring").Err()
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	runReq := RunRequest{
		TemplateID: pc.project.AnsibleRunTemplateID,
		ProjectID:  &pc.project.SemaphoreProjectID,
		Message:    fmt.Sprintf("Skyforge ansible run (%s)", pc.claims.Username),
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		writeAuditEvent(
			ctx,
			s.db,
			pc.claims.Username,
			containsUser(s.cfg.AdminUsers, pc.claims.Username),
			"",
			"project.run.ansible",
			pc.project.ID,
			fmt.Sprintf("templateId=%d semaphoreProjectId=%d", pc.project.AnsibleRunTemplateID, pc.project.SemaphoreProjectID),
		)
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	if err := ensureSemaphoreRepoAccessForUser(semaphoreCfg, pc.project, pc.claims.Username); err != nil {
		return nil, err
	}
	task, err := startSemaphoreRun(ctx, semaphoreCfg, s.db, pc.claims, runReq)
	if err != nil {
		return nil, err
	}
	taskJSON, err := toJSONMap(task)
	if err != nil {
		log.Printf("ansible task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.SemaphoreProjectID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
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

// RunProjectNetlab triggers a netlab run for a project.
//
//encore:api auth method=POST path=/api/projects/:id/runs/netlab-run
func (s *Service) RunProjectNetlab(ctx context.Context, id string, req *ProjectNetlabRunRequest) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.project.NetlabRunTemplateID == 0 || pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project is missing netlab run wiring").Err()
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
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
	env, err := fromJSONMap(req.Environment)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid environment").Err()
	}
	if env == nil {
		env = map[string]any{}
	}
	setEnvIfMissing := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if _, ok := env[key]; !ok {
			env[key] = value
		}
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
	apiURL := strings.TrimRight(fmt.Sprintf("https://%s/netlab", strings.TrimSpace(server.SSHHost)), "/")

	setEnvIfMissing("NETLAB_API_URL", apiURL)
	setEnvIfMissing("NETLAB_API_INSECURE", "true")
	setEnvIfMissing("NETLAB_ACTION", action)
	setEnvIfMissing("NETLAB_USER", strings.TrimSpace(pc.claims.Username))
	setEnvIfMissing("NETLAB_PROJECT", strings.TrimSpace(pc.project.Slug))
	setEnvIfMissing("NETLAB_DEPLOYMENT", deploymentName)
	setEnvIfMissing("NETLAB_MULTILAB_ID", strconv.Itoa(multilabNumericID))
	setEnvIfMissing("NETLAB_WORKSPACE_ROOT", workspaceRoot)
	if req.Cleanup {
		setEnvIfMissing("NETLAB_CLEANUP", "true")
	}

	// Backwards-compat for older runner scripts/config.
	projectDir := strings.TrimSpace(req.NetlabProjectDir)
	if projectDir == "" {
		projectDir = fmt.Sprintf("%s/%s/%s", workspaceRoot, strings.TrimSpace(pc.project.Slug), deploymentName)
	}
	setEnvIfMissing("NETLAB_PROJECT_DIR", projectDir)
	setEnvIfMissing("NETLAB_PROJECT_SLUG", pc.project.Slug)
	setEnvIfMissing("NETLAB_PROJECT_ID", pc.project.ID)
	setEnvIfMissing("NETLAB_DEPLOYMENT_ID", multilabID)
	setEnvIfMissing("NETLAB_PLUGIN", "multilab")
	setEnvIfMissing("NETLAB_SSH_HOST", strings.TrimSpace(server.SSHHost))
	setEnvIfMissing("NETLAB_SSH_USER", strings.TrimSpace(pc.claims.Username))
	setEnvIfMissing("NETLAB_STATE_ROOT", strings.TrimSpace(server.StateRoot))

	// If a Netlab topology template is selected, sync it into the user's workspace on the runner host.
	if req != nil && strings.TrimSpace(req.Template) != "" {
		if err := s.syncNetlabTopologyFile(ctx, pc, server, req.TemplateSource, req.TemplateRepo, req.TemplatesDir, req.Template, projectDir, strings.TrimSpace(pc.claims.Username)); err != nil {
			log.Printf("netlab template sync: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync netlab template").Err()
		}
	}

	// Semaphore doesn't reliably expose task-scoped "environment" values as OS env vars
	// for all runner types. Pass critical values as arguments as well (the runner script
	// maps these to NETLAB_* env vars if missing).
	args := []string{
		"--api-url", apiURL,
		"--api-insecure", "true",
		"--user", strings.TrimSpace(pc.claims.Username),
		"--project", strings.TrimSpace(pc.project.Slug),
		"--deployment", deploymentName,
		"--workspace-root", workspaceRoot,
		"--plugin", "multilab",
		"--multilab-id", strconv.Itoa(multilabNumericID),
	}
	if strings.TrimSpace(server.StateRoot) != "" {
		args = append(args, "--state-root", strings.TrimSpace(server.StateRoot))
	}

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge netlab run (%s)", pc.claims.Username)
	}
	runReq := RunRequest{
		TemplateID:  pc.project.NetlabRunTemplateID,
		ProjectID:   &pc.project.SemaphoreProjectID,
		Message:     message,
		GitBranch:   strings.TrimSpace(req.GitBranch),
		Arguments:   string(mustJSON(args)),
		Environment: nil,
	}
	envJSON, err := toJSONMap(env)
	if err != nil {
		log.Printf("netlab env encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode environment").Err()
	}
	runReq.Environment = envJSON

	// Ensure the repo has the current runner script before starting the run.
	// This repo is user-owned, so use the request identity for attribution.
	defaultBranch := strings.TrimSpace(pc.project.DefaultBranch)
	if defaultBranch == "" {
		defaultBranch = "master"
	}
	if err := ensureGiteaFile(s.cfg, pc.project.GiteaOwner, pc.project.GiteaRepo, "netlab/job/run_netlab_api.py", netlabAPIRunnerScript(), "chore: update netlab api runner", defaultBranch, pc.claims); err != nil {
		log.Printf("ensureGiteaFile netlab/job/run_netlab_api.py: %v", err)
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
			fmt.Sprintf("templateId=%d semaphoreProjectId=%d", pc.project.NetlabRunTemplateID, pc.project.SemaphoreProjectID),
		)
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	if err := ensureSemaphoreRepoAccessForUser(semaphoreCfg, pc.project, pc.claims.Username); err != nil {
		return nil, err
	}
	task, err := startSemaphoreRun(ctx, semaphoreCfg, s.db, pc.claims, runReq)
	if err != nil {
		return nil, err
	}
	taskJSON, err := toJSONMap(task)
	if err != nil {
		log.Printf("netlab task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.SemaphoreProjectID,
		Task:      taskJSON,
		User:      pc.claims.Username,
	}, nil
}

// RunProjectLabpp triggers a LabPP run for a project.
//
//encore:api auth method=POST path=/api/projects/:id/runs/labpp-run
func (s *Service) RunProjectLabpp(ctx context.Context, id string, req *ProjectLabppRunRequest) (*ProjectRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.project.LabppRunTemplateID == 0 || pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project is missing labpp run wiring").Err()
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
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

	env, err := fromJSONMap(req.Environment)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid environment").Err()
	}
	if env == nil {
		env = map[string]any{}
	}
	setEnvIfMissing := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if _, ok := env[key]; !ok {
			env[key] = value
		}
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

	setEnvIfMissing("LABPP_API_URL", apiURL)
	setEnvIfMissing("LABPP_API_INSECURE", fmt.Sprintf("%v", apiInsecure))
	setEnvIfMissing("LABPP_ACTION", action)
	setEnvIfMissing("LABPP_PROJECT", strings.TrimSpace(pc.project.Slug))
	setEnvIfMissing("LABPP_DEPLOYMENT", deployment)
	setEnvIfMissing("LABPP_TEMPLATES_ROOT", templatesRoot)
	setEnvIfMissing("LABPP_TEMPLATE", template)
	setEnvIfMissing("LABPP_LAB_PATH", labPath)
	setEnvIfMissing("LABPP_API_MAX_SECONDS", "1200")
	if threadCount > 0 {
		setEnvIfMissing("LABPP_THREAD_COUNT", strconv.Itoa(threadCount))
	}
	setEnvIfMissing("LABPP_EVE_URL", eveURL)
	setEnvIfMissing("LABPP_EVE_USERNAME", eveUsername)
	setEnvIfMissing("LABPP_EVE_PASSWORD", evePassword)

	args := []string{
		"--api-url", apiURL,
		"--api-insecure", fmt.Sprintf("%v", apiInsecure),
		"--action", action,
		"--project", strings.TrimSpace(pc.project.Slug),
		"--deployment", deployment,
		"--templates-root", templatesRoot,
		"--template", template,
		"--lab-path", labPath,
		"--eve-url", eveURL,
		"--eve-username", eveUsername,
	}
	if threadCount > 0 {
		args = append(args, "--thread-count", strconv.Itoa(threadCount))
	}

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge labpp run (%s)", pc.claims.Username)
	}
	runReq := RunRequest{
		TemplateID:  pc.project.LabppRunTemplateID,
		ProjectID:   &pc.project.SemaphoreProjectID,
		Message:     message,
		GitBranch:   strings.TrimSpace(req.GitBranch),
		Arguments:   string(mustJSON(args)),
		Environment: nil,
	}
	envJSON, err := toJSONMap(env)
	if err != nil {
		log.Printf("labpp env encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode environment").Err()
	}
	runReq.Environment = envJSON

	defaultBranch := strings.TrimSpace(pc.project.DefaultBranch)
	if defaultBranch == "" {
		defaultBranch = "master"
	}
	if err := ensureGiteaFile(s.cfg, pc.project.GiteaOwner, pc.project.GiteaRepo, "labpp/job/run_labpp_api.py", labppAPIRunnerScript(), "chore: update labpp api runner", defaultBranch, pc.claims); err != nil {
		log.Printf("ensureGiteaFile labpp/job/run_labpp_api.py: %v", err)
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
			fmt.Sprintf("templateId=%d semaphoreProjectId=%d", pc.project.LabppRunTemplateID, pc.project.SemaphoreProjectID),
		)
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	if err := ensureSemaphoreRepoAccessForUser(semaphoreCfg, pc.project, pc.claims.Username); err != nil {
		return nil, err
	}
	task, err := startSemaphoreRun(ctx, semaphoreCfg, s.db, pc.claims, runReq)
	if err != nil {
		return nil, err
	}
	taskJSON, err := toJSONMap(task)
	if err != nil {
		log.Printf("labpp task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &ProjectRunResponse{
		ProjectID: pc.project.SemaphoreProjectID,
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
		env["TF_VAR_aws_access_key_id"] = aws.ToString(roleCreds.AccessKeyId)
		env["TF_VAR_aws_secret_access_key"] = aws.ToString(roleCreds.SecretAccessKey)
		env["TF_VAR_aws_session_token"] = aws.ToString(roleCreds.SessionToken)
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
