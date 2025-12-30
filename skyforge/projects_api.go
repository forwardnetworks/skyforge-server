package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"encore.app/storage"
)

type ProjectsListParams struct {
	All string `query:"all" encore:"optional"`
}

type ProjectsListResponse struct {
	User     string            `json:"user"`
	Projects []SkyforgeProject `json:"projects"`
}

const defaultBlueprintCatalog = "skyforge/blueprints"

// GetProjects returns projects visible to the authenticated user.
//
//encore:api auth method=GET path=/api/projects tag:list-projects
func (s *Service) GetProjects(ctx context.Context, params *ProjectsListParams) (*ProjectsListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	isAdmin := isAdminUser(s.cfg, user.Username)

	projects, err := s.projectStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	all := params != nil && strings.EqualFold(strings.TrimSpace(params.All), "true")
	if !isAdmin && all {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("admin access required for all projects").Err()
	}
	if !isAdmin && !all {
		changed := false
		changedProjects := make([]SkyforgeProject, 0)
		for i := range projects {
			if role, ok := syncGroupMembershipForUser(&projects[i], claims); ok {
				changed = true
				changedProjects = append(changedProjects, projects[i])
				log.Printf("project group sync: %s -> %s (%s)", user.Username, projects[i].Slug, role)
			}
		}
		if changed {
			if err := s.projectStore.save(projects); err != nil {
				log.Printf("projects save after group sync: %v", err)
			} else {
				for _, p := range changedProjects {
					syncGiteaCollaboratorsForProject(s.cfg, p)
				}
			}
		}
		filtered := make([]SkyforgeProject, 0, len(projects))
		for _, p := range projects {
			if projectAccessLevelForClaims(s.cfg, p, claims) != "none" {
				filtered = append(filtered, p)
			}
		}
		projects = filtered
	}

	_ = ctx
	return &ProjectsListResponse{
		User:     user.Username,
		Projects: projects,
	}, nil
}

type ProjectCreateRequest struct {
	Name          string   `json:"name"`
	Slug          string   `json:"slug,omitempty"`
	Description   string   `json:"description,omitempty"`
	Blueprint     string   `json:"blueprint,omitempty"`
	IsPublic      bool     `json:"isPublic,omitempty"`
	SharedUsers   []string `json:"sharedUsers,omitempty"`
	AWSAccountID  string   `json:"awsAccountId,omitempty"`
	AWSRoleName   string   `json:"awsRoleName,omitempty"`
	AWSRegion     string   `json:"awsRegion,omitempty"`
	AWSAuthMethod string   `json:"awsAuthMethod,omitempty"`
	EveServer     string   `json:"eveServer,omitempty"`
	NetlabServer  string   `json:"netlabServer,omitempty"`
}

type BlueprintSyncResponse struct {
	Status string `json:"status"`
}

// CreateProject provisions a new Skyforge project.
//
//encore:api auth method=POST path=/api/projects
func (s *Service) CreateProject(ctx context.Context, req *ProjectCreateRequest) (*SkyforgeProject, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	slug := strings.TrimSpace(req.Slug)
	if slug == "" {
		slug = slugify(name)
	} else {
		slug = slugify(slug)
	}

	eveServer := strings.TrimSpace(req.EveServer)
	if eveServer != "" && eveServerByName(s.cfg.EveServers, eveServer) == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown eveServer").Err()
	}
	netlabServer := strings.TrimSpace(req.NetlabServer)
	if netlabServer != "" && netlabServerByNameForConfig(s.cfg, netlabServer) == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown netlabServer").Err()
	}

	ldapPassword, ok := getCachedLDAPPassword(user.Username)
	if !ok {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("LDAP password unavailable; reauthenticate").Err()
	}
	giteaCfg := s.cfg

	owner := user.Username
	repo := slug
	terraformStateKey := fmt.Sprintf("tf-%s/primary.tfstate", slug)
	artifactsBucket := storage.StorageBucketName

	projects, err := s.projectStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	for _, existing := range projects {
		if existing.Slug == slug {
			return &existing, nil
		}
	}

	if err := ensureGiteaUser(s.cfg, user.Username, ldapPassword); err != nil {
		log.Printf("ensureGiteaUser: %v", err)
	}

	blueprint := strings.TrimSpace(req.Blueprint)
	defaultBranch := "main"
	if strings.EqualFold(blueprint, defaultBlueprintCatalog) {
		if err := ensureBlueprintCatalogRepo(s.cfg, blueprint); err != nil {
			log.Printf("ensureBlueprintCatalogRepo: %v", err)
		}
	}
	if err := ensureGiteaRepoFromBlueprint(giteaCfg, owner, repo, blueprint); err != nil {
		if strings.TrimSpace(blueprint) == "" {
			log.Printf("ensureGiteaRepo: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision gitea repo").Err()
		}
		log.Printf("ensureGiteaRepoFromBlueprint fallback: %v", err)
		if err := ensureGiteaRepo(giteaCfg, owner, repo); err != nil {
			log.Printf("ensureGiteaRepo fallback: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision gitea repo").Err()
		}
		if err := syncGiteaRepoFromBlueprintWithSource(s.cfg, giteaCfg, owner, repo, blueprint, defaultBranch, claims); err != nil {
			log.Printf("syncGiteaRepoFromBlueprint fallback: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync blueprint").Err()
		}
	}

	defaultBranch, err = getGiteaRepoDefaultBranch(giteaCfg, owner, repo)
	if err != nil {
		log.Printf("getGiteaRepoDefaultBranch: %v", err)
		defaultBranch = "master"
	}

	storageEndpoint := strings.TrimSpace(s.cfg.Projects.ObjectStorageEndpoint)
	if storageEndpoint == "" {
		storageEndpoint = "minio:9000"
	}
	if !strings.Contains(storageEndpoint, "://") {
		storageEndpoint = "http://" + storageEndpoint
	}

	backendTF := fmt.Sprintf(`terraform {
  backend "s3" {
    endpoint                    = "%s"
    bucket                      = "terraform-state"
    key                         = "%s"
    region                      = "us-east-1"
    skip_region_validation      = true
    skip_credentials_validation = true
    use_path_style              = true
  }
}
`, storageEndpoint, terraformStateKey)
	if err := ensureGiteaFile(s.cfg, owner, repo, "backend.tf", backendTF, "chore: configure terraform backend", defaultBranch, claims); err != nil {
		log.Printf("ensureGiteaFile backend.tf: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to configure repo backend").Err()
	}

	compatTFVars := `variable "TF_IN_AUTOMATION" {
  type    = string
  default = ""
}
variable "AWS_EC2_METADATA_DISABLED" {
  type    = string
  default = ""
}
variable "AWS_SDK_LOAD_CONFIG" {
  type    = string
  default = ""
}
variable "AWS_PROFILE" {
  type    = string
  default = ""
}
variable "AWS_ACCESS_KEY_ID" {
  type    = string
  default = ""
}
variable "AWS_SECRET_ACCESS_KEY" {
  type    = string
  default = ""
}
variable "AWS_SESSION_TOKEN" {
  type    = string
  default = ""
}
variable "AWS_REGION" {
  type    = string
  default = ""
}
variable "TF_VAR_aws_region" {
  type    = string
  default = ""
}
variable "TF_VAR_aws_access_key_id" {
  type    = string
  default = ""
}
variable "TF_VAR_aws_secret_access_key" {
  type    = string
  default = ""
}
variable "TF_VAR_aws_session_token" {
  type    = string
  default = ""
}
variable "TF_VAR_scenario" {
  type    = string
  default = ""
}
variable "TF_VAR_artifacts_bucket" {
  type    = string
  default = ""
}
variable "TF_VAR_ssh_key_name" {
  type    = string
  default = ""
}
variable "ARM_TENANT_ID" {
  type    = string
  default = ""
}
variable "ARM_CLIENT_ID" {
  type    = string
  default = ""
}
variable "ARM_CLIENT_SECRET" {
  type    = string
  default = ""
}
variable "ARM_SUBSCRIPTION_ID" {
  type    = string
  default = ""
}
variable "TF_VAR_azure_subscription_id" {
  type    = string
  default = ""
}
variable "TF_VAR_azure_region" {
  type    = string
  default = ""
}
variable "GOOGLE_CREDENTIALS" {
  type    = string
  default = ""
}
variable "GOOGLE_PROJECT" {
  type    = string
  default = ""
}
variable "TF_VAR_gcp_project" {
  type    = string
  default = ""
}
variable "TF_VAR_gcp_region" {
  type    = string
  default = ""
}
`
	if err := ensureGiteaFile(s.cfg, owner, repo, "skyforge-compat.tf", compatTFVars, "chore: add skyforge terraform env compatibility", defaultBranch, claims); err != nil {
		log.Printf("ensureGiteaFile skyforge-compat.tf: %v", err)
	}

	desc := strings.TrimSpace(req.Description)
	if desc == "" {
		desc = "Provisioned by Skyforge."
	}
	if err := ensureGiteaFile(giteaCfg, owner, repo, "README.md", fmt.Sprintf("# %s\n\n%s\n", name, desc), "docs: add README", defaultBranch, claims); err != nil {
		log.Printf("ensureGiteaFile README.md: %v", err)
	}

	playbookYML := `- name: Skyforge placeholder playbook
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Placeholder
      debug:
        msg: "Replace playbook.yml with your Ansible automation."
`
	if err := ensureGiteaFile(giteaCfg, owner, repo, "playbook.yml", playbookYML, "chore: add placeholder ansible playbook", defaultBranch, claims); err != nil {
		log.Printf("ensureGiteaFile playbook.yml: %v", err)
	}

	semaphoreCfg := s.cfg
	semaphoreCfg.SemaphoreToken = ""
	semaphoreCfg.SemaphoreUsername = user.Username
	semaphoreCfg.SemaphorePassword = ldapPassword
	semaphoreCfg.SemaphorePasswordFile = ""

	semaphoreProjectID, err := ensureSemaphoreProject(semaphoreCfg, name)
	if err != nil {
		fallback := strings.TrimSpace(user.Email)
		if fallback == "" && strings.TrimSpace(s.cfg.CorpEmailDomain) != "" {
			fallback = fmt.Sprintf("%s@%s", user.Username, s.cfg.CorpEmailDomain)
		}
		if strings.Contains(fallback, "@") && !strings.EqualFold(fallback, semaphoreCfg.SemaphoreUsername) {
			altCfg := semaphoreCfg
			altCfg.SemaphoreUsername = fallback
			semaphoreProjectID, err = ensureSemaphoreProject(altCfg, name)
			if err == nil {
				semaphoreCfg = altCfg
			}
		}
	}
	if err != nil && strings.TrimSpace(s.cfg.SemaphoreAdminUsername) != "" {
		adminCfg := s.cfg
		adminCfg.SemaphoreToken = ""
		adminCfg.SemaphoreUsername = strings.TrimSpace(s.cfg.SemaphoreAdminUsername)
		adminCfg.SemaphorePassword = strings.TrimSpace(s.cfg.SemaphoreAdminPassword)
		adminCfg.SemaphorePasswordFile = strings.TrimSpace(s.cfg.SemaphoreAdminPasswordFile)
		if adminCfg.SemaphoreUsername != "" && (adminCfg.SemaphorePassword != "" || adminCfg.SemaphorePasswordFile != "") {
			adminProjectID, adminErr := ensureSemaphoreProject(adminCfg, name)
			if adminErr == nil {
				userID, userErr := findSemaphoreUserID(adminCfg, user.Username)
				if userErr != nil {
					log.Printf("findSemaphoreUserID: %v", userErr)
				} else if err := ensureSemaphoreProjectUser(adminCfg, adminProjectID, userID, "owner"); err != nil {
					log.Printf("ensureSemaphoreProjectUser: %v", err)
				}
				semaphoreProjectID = adminProjectID
				err = nil
			} else {
				log.Printf("ensureSemaphoreProject admin fallback: %v", adminErr)
			}
		}
	}
	if err != nil {
		log.Printf("ensureSemaphoreProject: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore project").Err()
	}

	keyID, err := ensureSemaphoreHTTPKey(semaphoreCfg, semaphoreProjectID, "gitea-http", giteaCfg.Projects.GiteaUsername, giteaCfg.Projects.GiteaPassword)
	if err != nil {
		log.Printf("ensureSemaphoreHTTPKey: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore key").Err()
	}

	giteaBase := giteaInternalBaseURL(s.cfg)
	if giteaBase == "" {
		log.Printf("ensureSemaphoreRepo: missing gitea base URL")
		return nil, errs.B().Code(errs.Unavailable).Msg("gitea base URL not configured").Err()
	}
	gitURL := fmt.Sprintf("%s/%s/%s.git", giteaBase, owner, repo)
	repoID, err := ensureSemaphoreRepo(semaphoreCfg, semaphoreProjectID, repo, gitURL, defaultBranch, keyID)
	if err != nil {
		log.Printf("ensureSemaphoreRepo: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore repository").Err()
	}

	projectEnv := map[string]string{
		"TF_IN_AUTOMATION":          "true",
		"TF_VAR_scenario":           "regular_cluster",
		"AWS_EC2_METADATA_DISABLED": "true",
		"TF_VAR_ssh_key_name":       "REPLACE_ME",
		"TF_VAR_artifacts_bucket":   "REPLACE_ME",
	}
	if strings.TrimSpace(s.cfg.AwsSSORegion) != "" {
		projectEnv["AWS_REGION"] = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	if s.cfg.Projects.ObjectStorageTerraformAccessKey != "" && s.cfg.Projects.ObjectStorageTerraformSecretKey != "" {
		projectEnv["AWS_ACCESS_KEY_ID"] = s.cfg.Projects.ObjectStorageTerraformAccessKey
		projectEnv["AWS_SECRET_ACCESS_KEY"] = s.cfg.Projects.ObjectStorageTerraformSecretKey
		projectEnv["AWS_SDK_LOAD_CONFIG"] = "0"
		projectEnv["AWS_PROFILE"] = ""
	}

	envID, err := ensureSemaphoreEnvironment(semaphoreCfg, semaphoreProjectID, "Terraform Defaults", projectEnv)
	if err != nil {
		log.Printf("ensureSemaphoreEnvironment: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore environment").Err()
	}

	terraformInventoryID, err := ensureSemaphoreInventory(semaphoreCfg, semaphoreProjectID, "terraform", "terraform\n")
	if err != nil {
		log.Printf("ensureSemaphoreInventory terraform: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore inventory").Err()
	}
	localInventoryID, err := ensureSemaphoreInventory(semaphoreCfg, semaphoreProjectID, "localhost", "localhost ansible_connection=local\n")
	if err != nil {
		log.Printf("ensureSemaphoreInventory localhost: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore inventory").Err()
	}

	tofuInitID, err := ensureSemaphoreTemplate(semaphoreCfg, semaphoreProjectID, map[string]any{
		"project_id":                    semaphoreProjectID,
		"repository_id":                 repoID,
		"environment_id":                envID,
		"inventory_id":                  terraformInventoryID,
		"name":                          "Tofu: AWS",
		"description":                   "Runs OpenTofu against AWS infrastructure.",
		"type":                          "apply",
		"app":                           "tofu",
		"playbook":                      ".",
		"git_branch":                    defaultBranch,
		"arguments":                     string(mustJSON([]string{})),
		"allow_override_args_in_task":   true,
		"allow_override_branch_in_task": true,
	})
	if err != nil {
		log.Printf("ensureSemaphoreTemplate tofu init: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore templates").Err()
	}

	tofuPlanID, err := ensureSemaphoreTemplate(semaphoreCfg, semaphoreProjectID, map[string]any{
		"project_id":                    semaphoreProjectID,
		"repository_id":                 repoID,
		"environment_id":                envID,
		"inventory_id":                  terraformInventoryID,
		"name":                          "Tofu: Azure",
		"description":                   "Runs OpenTofu against Azure infrastructure.",
		"type":                          "apply",
		"app":                           "tofu",
		"playbook":                      ".",
		"git_branch":                    defaultBranch,
		"arguments":                     string(mustJSON([]string{})),
		"allow_override_args_in_task":   true,
		"allow_override_branch_in_task": true,
	})
	if err != nil {
		log.Printf("ensureSemaphoreTemplate tofu plan: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore templates").Err()
	}

	tofuApplyID, err := ensureSemaphoreTemplate(semaphoreCfg, semaphoreProjectID, map[string]any{
		"project_id":                    semaphoreProjectID,
		"repository_id":                 repoID,
		"environment_id":                envID,
		"inventory_id":                  terraformInventoryID,
		"name":                          "Tofu: GCP",
		"description":                   "Runs OpenTofu against GCP infrastructure.",
		"type":                          "apply",
		"app":                           "tofu",
		"playbook":                      ".",
		"git_branch":                    defaultBranch,
		"arguments":                     string(mustJSON([]string{})),
		"allow_override_args_in_task":   false,
		"allow_override_branch_in_task": true,
	})
	if err != nil {
		log.Printf("ensureSemaphoreTemplate tofu apply: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore templates").Err()
	}

	ansibleRunID, err := ensureSemaphoreTemplate(semaphoreCfg, semaphoreProjectID, map[string]any{
		"project_id":                    semaphoreProjectID,
		"repository_id":                 repoID,
		"environment_id":                envID,
		"inventory_id":                  localInventoryID,
		"name":                          "Ansible: Run playbook.yml",
		"description":                   "Runs ansible-playbook playbook.yml (placeholder).",
		"app":                           "ansible",
		"playbook":                      "playbook.yml",
		"git_branch":                    defaultBranch,
		"arguments":                     string(mustJSON([]string{})),
		"allow_override_args_in_task":   true,
		"allow_override_branch_in_task": true,
	})
	if err != nil {
		log.Printf("ensureSemaphoreTemplate ansible run: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore templates").Err()
	}

	netlabScript := netlabAPIRunnerScript()
	if err := ensureGiteaFile(giteaCfg, owner, repo, "netlab/job/run_netlab_api.py", netlabScript, "chore: add netlab api runner", defaultBranch, claims); err != nil {
		log.Printf("ensureGiteaFile netlab/job/run_netlab_api.py: %v", err)
	}

	netlabRunID, err := ensureSemaphoreTemplate(semaphoreCfg, semaphoreProjectID, map[string]any{
		"project_id":                    semaphoreProjectID,
		"repository_id":                 repoID,
		"environment_id":                envID,
		"inventory_id":                  localInventoryID,
		"name":                          "Netlab: Run",
		"description":                   "Runs the Netlab API runner.",
		"app":                           "python",
		"playbook":                      "netlab/job/run_netlab_api.py",
		"git_branch":                    defaultBranch,
		"arguments":                     string(mustJSON([]string{})),
		"allow_override_args_in_task":   true,
		"allow_override_branch_in_task": true,
	})
	if err != nil {
		log.Printf("ensureSemaphoreTemplate netlab run: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore templates").Err()
	}

	labppScript := labppAPIRunnerScript()
	if err := ensureGiteaFile(giteaCfg, owner, repo, "labpp/job/run_labpp_api.py", labppScript, "chore: add labpp api runner", defaultBranch, claims); err != nil {
		log.Printf("ensureGiteaFile labpp/job/run_labpp_api.py: %v", err)
	}

	labppRunID, err := ensureSemaphoreTemplate(semaphoreCfg, semaphoreProjectID, map[string]any{
		"project_id":                    semaphoreProjectID,
		"repository_id":                 repoID,
		"environment_id":                envID,
		"inventory_id":                  localInventoryID,
		"name":                          "LabPP: Run",
		"description":                   "Runs the LabPP API runner.",
		"app":                           "python",
		"playbook":                      "labpp/job/run_labpp_api.py",
		"git_branch":                    defaultBranch,
		"arguments":                     string(mustJSON([]string{})),
		"allow_override_args_in_task":   true,
		"allow_override_branch_in_task": true,
	})
	if err != nil {
		log.Printf("ensureSemaphoreTemplate labpp run: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision semaphore templates").Err()
	}

	created := SkyforgeProject{
		ID:                   fmt.Sprintf("%d-%s", time.Now().Unix(), slug),
		Slug:                 slug,
		Name:                 name,
		Description:          strings.TrimSpace(req.Description),
		CreatedAt:            time.Now().UTC(),
		CreatedBy:            user.Username,
		IsPublic:             req.IsPublic,
		Owners:               []string{user.Username},
		Editors:              nil,
		Viewers:              normalizeUsernameList(req.SharedUsers),
		Blueprint:            strings.TrimSpace(req.Blueprint),
		DefaultBranch:        defaultBranch,
		TerraformStateKey:    terraformStateKey,
		TofuInitTemplateID:   tofuInitID,
		TofuPlanTemplateID:   tofuPlanID,
		TofuApplyTemplateID:  tofuApplyID,
		AnsibleRunTemplateID: ansibleRunID,
		NetlabRunTemplateID:  netlabRunID,
		LabppRunTemplateID:   labppRunID,
		AWSAccountID:         strings.TrimSpace(req.AWSAccountID),
		AWSRoleName:          strings.TrimSpace(req.AWSRoleName),
		AWSRegion:            strings.TrimSpace(req.AWSRegion),
		AWSAuthMethod:        strings.TrimSpace(strings.ToLower(req.AWSAuthMethod)),
		ArtifactsBucket:      artifactsBucket,
		EveServer:            eveServer,
		NetlabServer:         netlabServer,
		SemaphoreProjectID:   semaphoreProjectID,
		GiteaOwner:           owner,
		GiteaRepo:            repo,
	}
	if created.AWSAuthMethod == "" {
		created.AWSAuthMethod = "sso"
	}
	projects = append(projects, created)
	if err := s.projectStore.save(projects); err != nil {
		log.Printf("projects save: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist project").Err()
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if _, err := createNotification(
			ctx,
			s.db,
			user.Username,
			fmt.Sprintf("Project created: %s", created.Name),
			fmt.Sprintf("Skyforge provisioned project %s (%s).", created.Name, created.Slug),
			"SYSTEM",
			"projects",
			created.ID,
			"low",
		); err != nil {
			log.Printf("create notification (project): %v", err)
		}
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"project.create",
			created.ID,
			fmt.Sprintf("slug=%s repo=%s/%s semaphoreProjectId=%d", created.Slug, created.GiteaOwner, created.GiteaRepo, created.SemaphoreProjectID),
		)
	}
	syncGiteaCollaboratorsForProject(giteaCfg, created)
	return &created, nil
}

// SyncProjectBlueprint syncs a project's blueprint catalog into the repo.
//
//encore:api auth method=POST path=/api/projects/:projectID/blueprint/sync
func (s *Service) SyncProjectBlueprint(ctx context.Context, projectID string) (*BlueprintSyncResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, projectID)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	blueprint := strings.TrimSpace(pc.project.Blueprint)
	if blueprint == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("no blueprint configured").Err()
	}

	ldapPassword, ok := getCachedLDAPPassword(user.Username)
	if !ok {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("LDAP password unavailable; reauthenticate").Err()
	}
	if strings.EqualFold(blueprint, defaultBlueprintCatalog) {
		if err := ensureBlueprintCatalogRepo(s.cfg, blueprint); err != nil {
			log.Printf("ensureBlueprintCatalogRepo: %v", err)
		}
	}
	if err := ensureGiteaUser(s.cfg, user.Username, ldapPassword); err != nil {
		log.Printf("ensureGiteaUser: %v", err)
	}
	giteaCfg := s.cfg
	targetBranch := strings.TrimSpace(pc.project.DefaultBranch)
	if targetBranch == "" {
		targetBranch = "main"
	}
	if err := syncGiteaRepoFromBlueprintWithSource(s.cfg, giteaCfg, pc.project.GiteaOwner, pc.project.GiteaRepo, blueprint, targetBranch, pc.claims); err != nil {
		log.Printf("syncGiteaRepoFromBlueprint: %v", err)
		if fallbackErr := syncGiteaRepoFromBlueprintWithSource(s.cfg, s.cfg, pc.project.GiteaOwner, pc.project.GiteaRepo, blueprint, targetBranch, pc.claims); fallbackErr != nil {
			log.Printf("syncGiteaRepoFromBlueprint fallback: %v", fallbackErr)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync blueprint").Err()
		}
	}
	_ = ctx
	return &BlueprintSyncResponse{Status: "ok"}, nil
}
