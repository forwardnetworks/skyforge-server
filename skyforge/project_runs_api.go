package skyforge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
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
		return errs.B().Code(errs.FailedPrecondition).Msg("LDAP password unavailable; reauthenticate").Err()
	}
	gitBranch := strings.TrimSpace(project.DefaultBranch)
	if gitBranch == "" {
		gitBranch = "master"
	}
	giteaBase := normalizeGiteaBaseURL(cfg.GiteaBaseURL)
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

// RunProjectTofuPlanV1 triggers a tofu plan run for a project (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/runs/tofu-plan
func (s *Service) RunProjectTofuPlanV1(ctx context.Context, id string) (*ProjectRunResponse, error) {
	return s.RunProjectTofuPlan(ctx, id)
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

// RunProjectTofuApplyV1 triggers a tofu apply run for a project (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/runs/tofu-apply
func (s *Service) RunProjectTofuApplyV1(ctx context.Context, id string, params *ProjectTofuApplyParams) (*ProjectRunResponse, error) {
	return s.RunProjectTofuApply(ctx, id, params)
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

// RunProjectAnsibleV1 triggers an ansible run for a project (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/runs/ansible-run
func (s *Service) RunProjectAnsibleV1(ctx context.Context, id string) (*ProjectRunResponse, error) {
	return s.RunProjectAnsible(ctx, id)
}

type ProjectNetlabRunRequest struct {
	Message          string  `json:"message,omitempty"`
	GitBranch        string  `json:"gitBranch,omitempty"`
	Environment      JSONMap `json:"environment,omitempty"`
	NetlabPassword   string  `json:"netlabPassword,omitempty"`
	NetlabProjectDir string  `json:"netlabProjectDir,omitempty"`
	NetlabMultilabID string  `json:"netlabMultilabId,omitempty"`
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
	serverName := strings.TrimSpace(pc.project.NetlabServer)
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

	password := strings.TrimSpace(req.NetlabPassword)
	if password == "" {
		if raw, ok := env["NETLAB_SSH_PASSWORD"]; ok {
			if s, ok := raw.(string); ok {
				password = strings.TrimSpace(s)
			}
		}
	}
	if password == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabPassword is required (LDAP login for netlab host)").Err()
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

	projectDir := strings.TrimSpace(req.NetlabProjectDir)
	if projectDir == "" {
		projectDir = fmt.Sprintf("/home/%s/skyforge/%s/%s", pc.claims.Username, pc.project.ID, multilabID)
	}

	setEnvIfMissing("NETLAB_SSH_HOST", strings.TrimSpace(server.SSHHost))
	setEnvIfMissing("NETLAB_SSH_USER", strings.TrimSpace(pc.claims.Username))
	setEnvIfMissing("NETLAB_SSH_PASSWORD", password)
	setEnvIfMissing("NETLAB_PROJECT_DIR", projectDir)
	setEnvIfMissing("NETLAB_PROJECT_SLUG", pc.project.Slug)
	setEnvIfMissing("NETLAB_PROJECT_ID", pc.project.ID)
	setEnvIfMissing("NETLAB_DEPLOYMENT_ID", multilabID)
	setEnvIfMissing("NETLAB_PLUGIN", "multilab")
	setEnvIfMissing("NETLAB_MULTILAB_ID", multilabID)
	setEnvIfMissing("NETLAB_STATE_ROOT", strings.TrimSpace(server.StateRoot))

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge netlab run (%s)", pc.claims.Username)
	}
	runReq := RunRequest{
		TemplateID:  pc.project.NetlabRunTemplateID,
		ProjectID:   &pc.project.SemaphoreProjectID,
		Message:     message,
		GitBranch:   strings.TrimSpace(req.GitBranch),
		Environment: nil,
	}
	envJSON, err := toJSONMap(env)
	if err != nil {
		log.Printf("netlab env encode: %v", err)
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

// RunProjectNetlabV1 triggers a netlab run for a project (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/runs/netlab-run
func (s *Service) RunProjectNetlabV1(ctx context.Context, id string, req *ProjectNetlabRunRequest) (*ProjectRunResponse, error) {
	return s.RunProjectNetlab(ctx, id, req)
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
