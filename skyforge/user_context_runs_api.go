package skyforge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/aws/aws-sdk-go-v2/aws"
	"gopkg.in/yaml.v3"
)

type UserContextRunResponse struct {
	UserContextID string  `json:"userContextId"`
	Task          JSONMap `json:"task"`
	User          string  `json:"user"`
}

type UserContextTerraformApplyParams struct {
	Confirm        string `query:"confirm" encore:"optional"`
	Cloud          string `query:"cloud" encore:"optional"`
	Action         string `query:"action" encore:"optional"`
	TemplateSource string `query:"templateSource" encore:"optional"`
	TemplateRepo   string `query:"templateRepo" encore:"optional"`
	TemplatesDir   string `query:"templatesDir" encore:"optional"`
	Template       string `query:"template" encore:"optional"`
	DeploymentID   string `query:"deployment_id" encore:"optional"`
}

// RunUserContextTerraformPlan triggers a terraform plan run for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/runs/terraform-plan
func (s *Service) RunUserContextTerraformPlan(ctx context.Context, id string) (*UserContextRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getLatestDeploymentByTypeForUser(ctx, pc.claims.Username, pc.userContext.ID, "terraform")
	if err != nil {
		return nil, err
	}
	if dep == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("no terraform deployment configured").Err()
	}
	region := strings.TrimSpace(pc.userContext.AWSRegion)
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
	if s.cfg.UserContexts.ObjectStorageAccessKey != "" && s.cfg.UserContexts.ObjectStorageSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = s.cfg.UserContexts.ObjectStorageAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = s.cfg.UserContexts.ObjectStorageSecretKey
	}
	if shouldUseAWS(pc.userContext) {
		if strings.TrimSpace(pc.userContext.AWSAuthMethod) == "" {
			pc.userContext.AWSAuthMethod = "sso"
		}
		env["TF_VAR_aws_region"] = region
		if err := populateAWSAuthEnv(ctx, s.cfg, s.db, s.awsStore, pc.userContext, pc.claims.Username, env); err != nil {
			return nil, err
		}
	}
	if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.userContext, env); err != nil {
		return nil, err
	}
	if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.userContext, env); err != nil {
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
			"user.run.terraform-plan",
			pc.userContext.ID,
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

	deploymentEnv, err := s.mergeDeploymentEnvironment(ctx, pc.userContext.ID, user.Username, cfgAny)
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
	task, err := createTask(ctx, s.db, pc.userContext.ID, &dep.ID, "terraform-plan", fmt.Sprintf("Skyforge terraform plan (%s)", pc.claims.Username), pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("terraform plan task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &UserContextRunResponse{
		UserContextID: pc.userContext.ID,
		Task:          taskJSON,
		User:          pc.claims.Username,
	}, nil
}

// RunUserContextTerraformApply triggers a terraform apply run for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/runs/terraform-apply
func (s *Service) RunUserContextTerraformApply(ctx context.Context, id string, params *UserContextTerraformApplyParams) (*UserContextRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	region := strings.TrimSpace(pc.userContext.AWSRegion)
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
	if s.cfg.UserContexts.ObjectStorageAccessKey != "" && s.cfg.UserContexts.ObjectStorageSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = s.cfg.UserContexts.ObjectStorageAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = s.cfg.UserContexts.ObjectStorageSecretKey
	}
	if cloud == "aws" && shouldUseAWS(pc.userContext) {
		if strings.TrimSpace(pc.userContext.AWSAuthMethod) == "" {
			pc.userContext.AWSAuthMethod = "sso"
		}
		env["TF_VAR_aws_region"] = region
		if err := populateAWSAuthEnv(ctx, s.cfg, s.db, s.awsStore, pc.userContext, pc.claims.Username, env); err != nil {
			return nil, err
		}
	}
	if cloud == "azure" {
		if err := populateAzureAuthEnv(ctx, s.cfg, s.db, pc.userContext, env); err != nil {
			return nil, err
		}
	}
	if cloud == "gcp" {
		if err := populateGCPAuthEnv(ctx, s.cfg, s.db, pc.userContext, env); err != nil {
			return nil, err
		}
	}

	if deploymentID != "" {
		dep, err := s.getUserDeploymentForUser(ctx, pc.claims.Username, pc.userContext.ID, deploymentID)
		if err != nil {
			return nil, err
		}
		cfgAny, _ := fromJSONMap(dep.Config)
		deploymentEnv, err := s.mergeDeploymentEnvironment(ctx, pc.userContext.ID, user.Username, cfgAny)
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
			"user.run.terraform-apply",
			pc.userContext.ID,
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
	task, err := createTask(ctx, s.db, pc.userContext.ID, nil, fmt.Sprintf("terraform-%s", action), fmt.Sprintf("Skyforge terraform %s %s (%s)", action, strings.ToUpper(cloud), pc.claims.Username), pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("terraform apply task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &UserContextRunResponse{
		UserContextID: pc.userContext.ID,
		Task:          taskJSON,
		User:          pc.claims.Username,
	}, nil
}

// RunUserContextAnsible triggers an ansible run for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/runs/ansible-run
func (s *Service) RunUserContextAnsible(ctx context.Context, id string) (*UserContextRunResponse, error) {
	_ = ctx
	_ = id
	return nil, errs.B().Code(errs.Unimplemented).Msg("ansible runs are not supported in native mode").Err()
}

type UserContextNetlabRunRequest struct {
	Message              string  `json:"message,omitempty"`
	GitBranch            string  `json:"gitBranch,omitempty"`
	Environment          JSONMap `json:"environment,omitempty"`
	Action               string  `json:"action,omitempty"`  // up, create, restart, collect, status, down
	Cleanup              bool    `json:"cleanup,omitempty"` // for down/restart, remove workdir when true
	NetlabServer         string  `json:"netlabServer,omitempty"`
	NetlabPassword       string  `json:"netlabPassword,omitempty"`
	NetlabUserContextDir string  `json:"netlabUserContextDir,omitempty"`
	NetlabMultilabID     string  `json:"netlabMultilabId,omitempty"`
	NetlabDeployment     string  `json:"netlabDeployment,omitempty"`
	TopologyPath         string  `json:"topologyPath,omitempty"`   // remote workdir-relative (or absolute) topology file
	TopologyURL          string  `json:"topologyUrl,omitempty"`    // remote URL (only if netlab supports it)
	TemplateSource       string  `json:"templateSource,omitempty"` // user (default), blueprints, or custom
	TemplateRepo         string  `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir         string  `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/netlab)
	Template             string  `json:"template,omitempty"`       // filename (e.g. spine-leaf.yml)
	ClabTarball          string  `json:"clabTarball,omitempty"`
	ClabConfigDir        string  `json:"clabConfigDir,omitempty"`
	ClabCleanup          bool    `json:"clabCleanup,omitempty"`
}

type UserContextContainerlabRunRequest struct {
	Message        string  `json:"message,omitempty"`
	GitBranch      string  `json:"gitBranch,omitempty"`
	Environment    JSONMap `json:"environment,omitempty"`
	Action         string  `json:"action,omitempty"` // deploy, destroy
	NetlabServer   string  `json:"netlabServer,omitempty"`
	TemplateSource string  `json:"templateSource,omitempty"` // user (default), blueprints, or custom
	TemplateRepo   string  `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir   string  `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/containerlab)
	Template       string  `json:"template,omitempty"`       // filename (e.g. lab.yml)
	Deployment     string  `json:"deployment,omitempty"`     // deployment name for lab naming
	Reconfigure    bool    `json:"reconfigure,omitempty"`
}

type UserContextEveNgRunRequest struct {
	Message        string `json:"message,omitempty"`
	Action         string `json:"action,omitempty"` // create, start, stop, destroy
	EveServer      string `json:"eveServer,omitempty"`
	TemplateSource string `json:"templateSource,omitempty"` // user (default), blueprints, or custom
	TemplateRepo   string `json:"templateRepo,omitempty"`   // owner/repo or URL (custom only)
	TemplatesDir   string `json:"templatesDir,omitempty"`   // repo-relative directory (default: blueprints/eve-ng)
	Template       string `json:"template,omitempty"`       // directory name under templates dir
	Deployment     string `json:"deployment,omitempty"`     // deployment name for lab naming
	DeploymentID   string `json:"deploymentId,omitempty"`
	LabPath        string `json:"labPath,omitempty"`
}

// RunUserContextNetlab triggers a netlab run for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/runs/netlab-run
func (s *Service) RunUserContextNetlab(ctx context.Context, id string, req *UserContextNetlabRunRequest) (*UserContextRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
		req = &UserContextNetlabRunRequest{}
	}

	templateSource := strings.ToLower(strings.TrimSpace(req.TemplateSource))
	if templateSource == "" {
		templateSource = "user"
	}
	serverRef := strings.TrimSpace(req.NetlabServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.userContext.NetlabServer)
	}
	server, err := s.resolveNetlabServerConfig(ctx, pc, serverRef)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
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

	runID := strings.TrimSpace(req.NetlabMultilabID)
	if runID == "" {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err == nil {
			runID = hex.EncodeToString(buf)
		} else {
			runID = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
	}

	deploymentName := strings.TrimSpace(req.NetlabDeployment)
	if deploymentName == "" {
		deploymentName = runID
	}

	userContextRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)

	// Backwards-compat for older runner scripts/config.
	userContextDir := strings.TrimSpace(req.NetlabUserContextDir)
	if userContextDir == "" {
		userContextDir = fmt.Sprintf("%s/%s/%s", userContextRoot, strings.TrimSpace(pc.userContext.Slug), deploymentName)
	}

	topologyPath := strings.TrimSpace(req.TopologyPath)
	topologyURL := strings.TrimSpace(req.TopologyURL)
	templateName := strings.Trim(strings.TrimSpace(req.Template), "/")
	if topologyPath == "" && topologyURL == "" {
		if templateName != "" {
			owner := pc.userContext.GiteaOwner
			repo := pc.userContext.GiteaRepo
			branch := strings.TrimSpace(pc.userContext.DefaultBranch)
			policy, _ := loadGovernancePolicy(ctx, s.db)

			switch templateSource {
			case "blueprints", "blueprint":
				ref := strings.TrimSpace(pc.userContext.Blueprint)
				if ref == "" {
					ref = "skyforge/blueprints"
				}
				if strings.Contains(ref, "://") {
					if u, err := url.Parse(ref); err == nil {
						ref = strings.Trim(strings.TrimPrefix(u.Path, "/"), "/")
					}
				}
				parts := strings.Split(strings.Trim(ref, "/"), "/")
				if len(parts) < 2 {
					return nil, errs.B().Code(errs.InvalidArgument).Msg("blueprints repo must be of form owner/repo").Err()
				}
				owner, repo = parts[0], parts[1]
				branch = ""
			case "user":
				if !pc.userContext.IsPublic {
					return nil, errs.B().Code(errs.FailedPrecondition).Msg("user repo is private; netlab BYOS requires a public topologyUrl (use the public blueprints repo or make the repo public)").Err()
				}
			case "custom", "external":
				// Allowed only when enabled; URL access still depends on repo visibility.
				if strings.TrimSpace(req.TemplateRepo) == "" {
					return nil, errs.B().Code(errs.InvalidArgument).Msg("templateRepo is required for custom/external template source").Err()
				}
				ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, templateSource, strings.TrimSpace(req.TemplateRepo))
				if err != nil {
					if strings.Contains(strings.ToLower(err.Error()), "not enabled") {
						return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
					}
					if strings.Contains(strings.ToLower(err.Error()), "not allowed") {
						return nil, errs.B().Code(errs.PermissionDenied).Msg(err.Error()).Err()
					}
					return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
				}
				owner, repo, branch = ref.Owner, ref.Repo, ref.Branch
			default:
				return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown template source").Err()
			}

			if branch == "" {
				branch = "main"
				if b, err := getGiteaRepoDefaultBranch(s.cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
					branch = strings.TrimSpace(b)
				}
			}

			templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
			if templatesDir == "" {
				templatesDir = "blueprints/netlab"
				if templateSource == "blueprints" || templateSource == "blueprint" || templateSource == "external" {
					templatesDir = "netlab"
				}
			}
			if !isSafeRelativePath(templateName) || !isSafeRelativePath(templatesDir) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a safe repo-relative path").Err()
			}
			filePath := path.Join(templatesDir, templateName)
			topologyURL = giteaRawFileURL(s.cfg, owner, repo, branch, filePath)
		} else {
			topologyPath = "topology.yml"
		}
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
			"user.run.netlab",
			pc.userContext.ID,
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
		"dedupeKey":  fmt.Sprintf("netlab:%s:%s:%s", pc.userContext.ID, action, deploymentName),
		"spec": map[string]any{
			"action":          action,
			"server":          serverRef,
			"serverLabel":     strings.TrimSpace(server.Name),
			"deployment":      deploymentName,
			"userContextRoot": userContextRoot,
			"userContextDir":  strings.TrimSpace(userContextDir),
			"topologyPath":    topologyPath,
			"topologyUrl":     topologyURL,
			"cleanup":         req.Cleanup,
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
		task, err = createTaskAllowActive(ctx, s.db, pc.userContext.ID, nil, "netlab-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.userContext.ID, nil, "netlab-run", message, pc.claims.Username, meta)
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
	return &UserContextRunResponse{
		UserContextID: pc.userContext.ID,
		Task:          taskJSON,
		User:          pc.claims.Username,
	}, nil
}

// RunUserContextContainerlab triggers a Containerlab run for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/runs/containerlab-run
func (s *Service) RunUserContextContainerlab(ctx context.Context, id string, req *UserContextContainerlabRunRequest) (*UserContextRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
		req = &UserContextContainerlabRunRequest{}
	}

	serverRef := strings.TrimSpace(req.NetlabServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.userContext.NetlabServer)
	}
	server, err := s.resolveContainerlabServerConfig(ctx, pc, serverRef)
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
	labName := containerlabLabName(pc.userContext.Slug, deploymentName)

	var topologyJSON string
	var topologySourceURL string
	if action == "deploy" {
		templatesDir := normalizeContainerlabTemplatesDir(req.TemplateSource, req.TemplatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		filePath := path.Join(templatesDir, template)

		// Prefer topologySourceUrl (clab-api-server supports git/raw URLs) to avoid sending full topology content.
		// For private personal repos, the BYOS host might not be able to fetch the raw URL, so we keep a
		// fallback mode that uploads topology content directly.
		templateSource := strings.ToLower(strings.TrimSpace(req.TemplateSource))
		if templateSource == "" {
			templateSource = "user"
		}

		// External repos can be either a Gitea owner/repo or a full git URL.
		if templateSource == "external" {
			found := externalTemplateRepoByIDForContext(pc, strings.TrimSpace(req.TemplateRepo))
			if found == nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown external repo").Err()
			}
			repoRef := strings.TrimSpace(found.Repo)
			branch := strings.TrimSpace(found.DefaultBranch)
			if branch == "" {
				branch = "main"
			}
			if isGitURL(repoRef) {
				if s.db == nil || s.box == nil {
					return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
				}
				creds, err := ensureUserGitDeployKey(ctx, s.db, s.box, pc.claims.Username)
				if err != nil {
					return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
				}
				body, err := readRepoFileBytes(ctx, creds, repoRef, branch, filePath)
				if err != nil {
					log.Printf("containerlab external template read: %v", err)
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
			} else {
				policy, _ := loadGovernancePolicy(ctx, s.db)
				ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, req.TemplateSource, req.TemplateRepo)
				if err != nil {
					return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
				}
				topologySourceURL = giteaRawFileURL(s.cfg, ref.Owner, ref.Repo, ref.Branch, filePath)
			}
		} else {
			policy, _ := loadGovernancePolicy(ctx, s.db)
			ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, req.TemplateSource, req.TemplateRepo)
			if err != nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
			}

			shouldUseSource := templateSource != "user" || pc.userContext.IsPublic
			if shouldUseSource {
				topologySourceURL = giteaRawFileURL(s.cfg, ref.Owner, ref.Repo, ref.Branch, filePath)
			} else {
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
		}
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
			"user.run.containerlab",
			pc.userContext.ID,
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
		"dedupeKey": fmt.Sprintf("containerlab:%s:%s:%s", pc.userContext.ID, action, labName),
		"spec": map[string]any{
			"action":            action,
			"netlabServer":      serverRef,
			"serverLabel":       strings.TrimSpace(server.Name),
			"deployment":        deploymentName,
			"labName":           labName,
			"reconfigure":       reconfigure,
			"topologyJSON":      topologyJSON,
			"topologySourceUrl": strings.TrimSpace(topologySourceURL),
			"environment":       envMap,
		},
	})
	if err != nil {
		log.Printf("containerlab meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}
	allowActive := action == "destroy"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.userContext.ID, nil, "containerlab-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.userContext.ID, nil, "containerlab-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("containerlab task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &UserContextRunResponse{
		UserContextID: pc.userContext.ID,
		Task:          taskJSON,
		User:          pc.claims.Username,
	}, nil
}

// RunUserContextEveNg triggers an EVE-NG lab run for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/runs/eve-ng-run
func (s *Service) RunUserContextEveNg(ctx context.Context, id string, req *UserContextEveNgRunRequest) (*UserContextRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
		req = &UserContextEveNgRunRequest{}
	}

	serverRef := strings.TrimSpace(req.EveServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.userContext.EveServer)
	}
	server, err := s.resolveEveServerConfig(ctx, pc, serverRef)
	if err != nil {
		return nil, err
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "start"
	}
	switch action {
	case "create", "start", "stop", "destroy":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid eve-ng action (use create, start, stop, or destroy)").Err()
	}

	templateSource := strings.ToLower(strings.TrimSpace(req.TemplateSource))
	if templateSource == "" {
		templateSource = "blueprints"
	}
	templatesDir := normalizeEveNgTemplatesDir(templateSource, req.TemplatesDir)
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}
	template := strings.TrimSpace(req.Template)
	if template == "" && action != "destroy" && action != "stop" && strings.TrimSpace(req.LabPath) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}

	deploymentName := strings.TrimSpace(req.Deployment)
	if deploymentName == "" {
		deploymentName = strings.TrimSpace(template)
	}
	labPath := strings.TrimSpace(req.LabPath)
	if labPath == "" {
		labPath = path.Join("skyforge", pc.userContext.Slug, deploymentName+".unl")
	}

	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = fmt.Sprintf("Skyforge eve-ng run (%s)", pc.claims.Username)
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
			"user.run.eve-ng",
			pc.userContext.ID,
			fmt.Sprintf("action=%s server=%s", action, strings.TrimSpace(server.Name)),
		)
	}

	meta, err := toJSONMap(map[string]any{
		"action":    action,
		"server":    strings.TrimSpace(server.Name),
		"serverRef": serverRef,
		"labPath":   labPath,
		"template":  template,
		"priority":  taskPriorityInteractive,
		"dedupeKey": fmt.Sprintf("eve-ng:%s:%s:%s", pc.userContext.ID, action, labPath),
		"spec": map[string]any{
			"action":         action,
			"server":         serverRef,
			"serverLabel":    strings.TrimSpace(server.Name),
			"deployment":     deploymentName,
			"deploymentId":   strings.TrimSpace(req.DeploymentID),
			"templateSource": templateSource,
			"templateRepo":   strings.TrimSpace(req.TemplateRepo),
			"templatesDir":   templatesDir,
			"template":       template,
			"labPath":        labPath,
		},
	})
	if err != nil {
		log.Printf("eve-ng meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}

	allowActive := action == "stop" || action == "destroy"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.userContext.ID, nil, "eve-ng-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.userContext.ID, nil, "eve-ng-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("eve-ng task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &UserContextRunResponse{
		UserContextID: pc.userContext.ID,
		Task:          taskJSON,
		User:          pc.claims.Username,
	}, nil
}

func populateAWSAuthEnv(ctx context.Context, cfg Config, db *sql.DB, store awsSSOTokenStore, userContext SkyforgeWorkspace, username string, env map[string]any) error {
	switch strings.ToLower(strings.TrimSpace(userContext.AWSAuthMethod)) {
	case "sso":
		accountID := strings.TrimSpace(userContext.AWSAccountID)
		roleName := strings.TrimSpace(userContext.AWSRoleName)
		if accountID == "" || roleName == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("user context is missing awsAccountId/awsRoleName").Err()
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
		rec, err := getUserContextAWSStaticCredentials(ctx, db, newSecretBox(cfg.SessionSecret), userContext.ID)
		if err != nil {
			log.Printf("aws static get: %v", err)
			return errs.B().Code(errs.Unavailable).Msg("aws static credentials unavailable").Err()
		}
		if rec == nil || rec.AccessKeyID == "" || rec.SecretAccessKey == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("aws static credentials are not configured for this user context").Err()
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

func shouldUseAWS(userContext SkyforgeWorkspace) bool {
	authMethod := strings.ToLower(strings.TrimSpace(userContext.AWSAuthMethod))
	if authMethod == "" {
		authMethod = "sso"
	}
	switch authMethod {
	case "static":
		return true
	case "sso":
		return strings.TrimSpace(userContext.AWSAccountID) != "" && strings.TrimSpace(userContext.AWSRoleName) != ""
	default:
		return false
	}
}

func populateAzureAuthEnv(ctx context.Context, cfg Config, db *sql.DB, userContext SkyforgeWorkspace, env map[string]any) error {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserContextAzureCredentials(ctx, db, newSecretBox(cfg.SessionSecret), userContext.ID)
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

func populateGCPAuthEnv(ctx context.Context, cfg Config, db *sql.DB, userContext SkyforgeWorkspace, env map[string]any) error {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserContextGCPCredentials(ctx, db, newSecretBox(cfg.SessionSecret), userContext.ID)
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

// Legacy wrappers kept until Encore stubs are regenerated.
