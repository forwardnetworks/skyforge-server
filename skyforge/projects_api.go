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

type workspaceCreateContextKey string

const workspaceCreateInternalKey workspaceCreateContextKey = "allow_workspace_create_internal"

type WorkspacesListParams struct {
	All string `query:"all" encore:"optional"`
}

type WorkspacesListResponse struct {
	User       string              `json:"user"`
	Workspaces []SkyforgeWorkspace `json:"workspaces"`
}

const defaultBlueprintCatalog = "skyforge/blueprints"

func defaultWorkspaceSlug(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	if normalized == "" {
		normalized = "user"
	}
	return slugify(fmt.Sprintf("workspace-%s", normalized))
}

func defaultWorkspaceName(username string) string {
	normalized := strings.TrimSpace(username)
	if normalized == "" {
		normalized = "User"
	}
	return fmt.Sprintf("%s Workspace", normalized)
}

func defaultWorkspaceRepo() string {
	return "workspace"
}

func (s *Service) ensureDefaultWorkspace(ctx context.Context, user *AuthUser) (*SkyforgeWorkspace, error) {
	if user == nil {
		return nil, nil
	}
	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, err
	}
	baseSlug := defaultWorkspaceSlug(user.Username)
	slug := baseSlug
	for _, w := range workspaces {
		if strings.EqualFold(w.CreatedBy, user.Username) && strings.EqualFold(w.Slug, baseSlug) {
			s.maybeQueueUserBootstrap(ctx, w.ID, user)
			return &w, nil
		}
		if strings.EqualFold(w.Slug, slug) && !strings.EqualFold(w.CreatedBy, user.Username) {
			slug = fmt.Sprintf("%s-%d", baseSlug, time.Now().Unix()%10000)
		}
	}
	req := &WorkspaceCreateRequest{
		Name:      defaultWorkspaceName(user.Username),
		Slug:      slug,
		Blueprint: defaultBlueprintCatalog,
	}
	internalCtx := context.WithValue(ctx, workspaceCreateInternalKey, true)
	created, err := s.CreateWorkspace(internalCtx, req)
	if err != nil {
		return nil, err
	}
	if created != nil {
		s.maybeQueueUserBootstrap(ctx, created.ID, user)
	}
	return created, nil
}

func (s *Service) maybeQueueUserBootstrap(ctx context.Context, workspaceID string, user *AuthUser) {
	if s == nil || s.db == nil || user == nil {
		return
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return
	}
	username := strings.TrimSpace(user.Username)
	if username == "" {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dedupeKey := fmt.Sprintf("user-bootstrap:%s", strings.ToLower(username))
	if recent, err := hasRecentTaskByDedupeKey(ctx, s.db, "user-bootstrap", dedupeKey, 30*time.Minute); err == nil && recent {
		return
	}
	meta, err := toJSONMap(map[string]any{
		"dedupeKey": dedupeKey,
		"spec": map[string]any{
			"username":    username,
			"displayName": strings.TrimSpace(user.DisplayName),
			"email":       strings.TrimSpace(user.Email),
		},
	})
	if err != nil {
		return
	}
	task, err := createTask(ctx, s.db, workspaceID, nil, "user-bootstrap", "Skyforge user bootstrap", username, meta)
	if err != nil {
		return
	}
	s.queueTask(task)
}

func (s *Service) resolveWorkspaceForUser(ctx context.Context, user *AuthUser, workspaceKey string) (*SkyforgeWorkspace, error) {
	workspaceKey = strings.TrimSpace(workspaceKey)
	if workspaceKey == "" || isPersonalWorkspaceKey(workspaceKey) {
		workspace, err := s.ensureDefaultWorkspace(ctx, user)
		if err != nil {
			return nil, err
		}
		if workspace == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("workspace_id is required").Err()
		}
		return workspace, nil
	}
	wc, err := s.workspaceContextForUser(user, workspaceKey)
	if err != nil {
		return nil, err
	}
	return &wc.workspace, nil
}

// GetWorkspaces returns workspaces visible to the authenticated user.
//
//encore:api auth method=GET path=/api/workspaces tag:list-workspaces
func (s *Service) GetWorkspaces(ctx context.Context, params *WorkspacesListParams) (*WorkspacesListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	isAdmin := isAdminUser(s.cfg, user.Username)

	if _, err := s.ensureDefaultWorkspace(ctx, user); err != nil {
		log.Printf("default workspace ensure: %v", err)
	}
	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	all := false
	_ = params
	if !isAdmin && !all {
		changed := false
		changedWorkspaces := make([]SkyforgeWorkspace, 0)
		for i := range workspaces {
			if role, ok := syncGroupMembershipForUser(&workspaces[i], claims); ok {
				changed = true
				changedWorkspaces = append(changedWorkspaces, workspaces[i])
				log.Printf("workspace group sync: %s -> %s (%s)", user.Username, workspaces[i].Slug, role)
			}
		}
		if changed {
			updatedAll := true
			for _, w := range changedWorkspaces {
				if err := s.workspaceStore.upsert(w); err != nil {
					updatedAll = false
					log.Printf("workspace upsert after group sync (%s): %v", w.ID, err)
				}
			}
			if updatedAll {
				for _, w := range changedWorkspaces {
					syncGiteaCollaboratorsForWorkspace(s.cfg, w)
				}
			}
		}
		filtered := make([]SkyforgeWorkspace, 0, len(workspaces))
		for _, w := range workspaces {
			if workspaceAccessLevelForClaims(s.cfg, w, claims) != "none" {
				filtered = append(filtered, w)
			}
		}
		workspaces = filtered
	}
	if !all {
		baseSlug := defaultWorkspaceSlug(user.Username)
		personal := (*SkyforgeWorkspace)(nil)
		for i := range workspaces {
			if strings.EqualFold(workspaces[i].CreatedBy, user.Username) && strings.EqualFold(workspaces[i].Slug, baseSlug) {
				w := workspaces[i]
				personal = &w
				break
			}
		}
		if personal == nil {
			for i := range workspaces {
				if strings.EqualFold(workspaces[i].CreatedBy, user.Username) {
					w := workspaces[i]
					personal = &w
					break
				}
			}
		}
		if personal != nil {
			workspaces = []SkyforgeWorkspace{*personal}
		}
	}

	_ = ctx
	return &WorkspacesListResponse{
		User:       user.Username,
		Workspaces: workspaces,
	}, nil
}

type WorkspaceCreateRequest struct {
	Name                       string                 `json:"name"`
	Slug                       string                 `json:"slug,omitempty"`
	Description                string                 `json:"description,omitempty"`
	Blueprint                  string                 `json:"blueprint,omitempty"`
	IsPublic                   bool                   `json:"isPublic,omitempty"`
	SharedUsers                []string               `json:"sharedUsers,omitempty"`
	AWSAccountID               string                 `json:"awsAccountId,omitempty"`
	AWSRoleName                string                 `json:"awsRoleName,omitempty"`
	AWSRegion                  string                 `json:"awsRegion,omitempty"`
	AWSAuthMethod              string                 `json:"awsAuthMethod,omitempty"`
	NetlabServer               string                 `json:"netlabServer,omitempty"`
	AllowExternalTemplateRepos bool                   `json:"allowExternalTemplateRepos,omitempty"`
	AllowCustomNetlabServers   bool                   `json:"allowCustomNetlabServers,omitempty"`
	ExternalTemplateRepos      []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
}

type BlueprintSyncResponse struct {
	Status string `json:"status"`
}

// CreateWorkspace provisions a new Skyforge workspace.
//
//encore:api auth method=POST path=/api/workspaces
func (s *Service) CreateWorkspace(ctx context.Context, req *WorkspaceCreateRequest) (*SkyforgeWorkspace, error) {
	if allow, _ := ctx.Value(workspaceCreateInternalKey).(bool); !allow {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("workspace management has been removed; personal scope is automatic").Err()
	}
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

	if strings.TrimSpace(req.NetlabServer) != "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer cannot be set at workspace creation (configure in workspace settings)").Err()
	}
	netlabServer := ""
	externalRepos := []ExternalTemplateRepo{}
	if req.AllowExternalTemplateRepos {
		var err error
		externalRepos, err = validateExternalTemplateRepos(req.ExternalTemplateRepos)
		if err != nil {
			return nil, err
		}
	}

	giteaCfg := s.cfg

	owner := user.Username
	repo := slug
	if slug == defaultWorkspaceSlug(user.Username) {
		repo = defaultWorkspaceRepo()
	}
	terraformStateKey := fmt.Sprintf("tf-%s/primary.tfstate", slug)
	artifactsBucket := storage.StorageBucketName

	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	for _, existing := range workspaces {
		if existing.Slug == slug {
			return &existing, nil
		}
	}

	profile := &UserProfile{
		Authenticated: true,
		Username:      user.Username,
		DisplayName:   strings.TrimSpace(user.DisplayName),
		Email:         strings.TrimSpace(user.Email),
		Groups:        user.Groups,
		IsAdmin:       isAdminUser(s.cfg, user.Username),
	}
	if profile.DisplayName == "" {
		profile.DisplayName = profile.Username
	}
	if profile.Email == "" && strings.TrimSpace(s.cfg.CorpEmailDomain) != "" {
		profile.Email = fmt.Sprintf("%s@%s", profile.Username, strings.TrimSpace(s.cfg.CorpEmailDomain))
	}
	// Provisioning the Gitea user is a best-effort side-effect. Workspace creation
	// should succeed even if the downstream integration is temporarily unavailable.
	if err := ensureGiteaUserFromProfile(s.cfg, profile); err != nil {
		log.Printf("ensureGiteaUserFromProfile: %v", err)
	}

	blueprint := strings.TrimSpace(req.Blueprint)
	if blueprint == "" {
		blueprint = defaultBlueprintCatalog
	}
	defaultBranch := "main"
	if strings.EqualFold(blueprint, defaultBlueprintCatalog) {
		if err := ensureBlueprintCatalogRepo(s.cfg, blueprint); err != nil {
			log.Printf("ensureBlueprintCatalogRepo: %v", err)
		}
	}
	// Workspace creation should not be blocked on provisioning downstream tooling.
	// Gitea provisioning/sync is best-effort and can be retried via workspace sync.
	{
		repoPrivate := !req.IsPublic
		if err := ensureGiteaRepoFromBlueprint(giteaCfg, owner, repo, blueprint, repoPrivate); err != nil {
			if strings.TrimSpace(blueprint) == "" {
				log.Printf("ensureGiteaRepo: %v", err)
			} else {
				log.Printf("ensureGiteaRepoFromBlueprint fallback: %v", err)
				if err := ensureGiteaRepo(giteaCfg, owner, repo, repoPrivate); err != nil {
					log.Printf("ensureGiteaRepo fallback: %v", err)
				} else if err := syncGiteaRepoFromBlueprintWithSource(s.cfg, giteaCfg, owner, repo, blueprint, defaultBranch, claims); err != nil {
					log.Printf("syncGiteaRepoFromBlueprint fallback: %v", err)
				}
			}
		}

		if branch, err := getGiteaRepoDefaultBranch(giteaCfg, owner, repo); err != nil {
			log.Printf("getGiteaRepoDefaultBranch: %v", err)
		} else if strings.TrimSpace(branch) != "" {
			defaultBranch = branch
		}
	}

	terraformInitID := 0
	terraformPlanID := 0
	terraformApplyID := 0
	ansibleRunID := 0
	netlabRunID := 0
	containerlabRunID := 0

	created := SkyforgeWorkspace{
		ID:                         fmt.Sprintf("%d-%s", time.Now().Unix(), slug),
		Slug:                       slug,
		Name:                       name,
		Description:                strings.TrimSpace(req.Description),
		CreatedAt:                  time.Now().UTC(),
		CreatedBy:                  user.Username,
		IsPublic:                   req.IsPublic,
		Owners:                     []string{user.Username},
		Editors:                    nil,
		Viewers:                    normalizeUsernameList(req.SharedUsers),
		Blueprint:                  strings.TrimSpace(req.Blueprint),
		DefaultBranch:              defaultBranch,
		TerraformStateKey:          terraformStateKey,
		TerraformInitTemplateID:    terraformInitID,
		TerraformPlanTemplateID:    terraformPlanID,
		TerraformApplyTemplateID:   terraformApplyID,
		AnsibleRunTemplateID:       ansibleRunID,
		NetlabRunTemplateID:        netlabRunID,
		ContainerlabRunTemplateID:  containerlabRunID,
		AWSAccountID:               strings.TrimSpace(req.AWSAccountID),
		AWSRoleName:                strings.TrimSpace(req.AWSRoleName),
		AWSRegion:                  strings.TrimSpace(req.AWSRegion),
		AWSAuthMethod:              strings.TrimSpace(strings.ToLower(req.AWSAuthMethod)),
		ArtifactsBucket:            artifactsBucket,
		NetlabServer:               netlabServer,
		AllowExternalTemplateRepos: req.AllowExternalTemplateRepos,
		AllowCustomNetlabServers:   req.AllowCustomNetlabServers,
		ExternalTemplateRepos:      externalRepos,
		GiteaOwner:                 owner,
		GiteaRepo:                  repo,
	}
	if created.AWSAuthMethod == "" {
		created.AWSAuthMethod = "sso"
	}
	if err := s.workspaceStore.upsert(created); err != nil {
		log.Printf("workspace upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist workspace").Err()
	}
	if s.db != nil {
		_ = notifyWorkspacesUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if _, err := createNotification(
			ctx,
			s.db,
			user.Username,
			fmt.Sprintf("Workspace created: %s", created.Name),
			fmt.Sprintf("Skyforge provisioned workspace %s (%s).", created.Name, created.Slug),
			"SYSTEM",
			"workspaces",
			created.ID,
			"low",
		); err != nil {
			log.Printf("create notification (workspace): %v", err)
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
			"workspace.create",
			created.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", created.Slug, created.GiteaOwner, created.GiteaRepo),
		)
	}
	syncGiteaCollaboratorsForWorkspace(giteaCfg, created)

	// Offload repo seeding + blueprint sync to the task queue for durability/retries.
	// Workspace creation should succeed even if downstream provisioning is temporarily unavailable.
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		meta, err := toJSONMap(map[string]any{
			"dedupeKey": fmt.Sprintf("workspace-bootstrap:%s", strings.TrimSpace(created.ID)),
			"spec":      map[string]any{},
		})
		if err != nil {
			log.Printf("workspace bootstrap meta encode: %v", err)
		} else if task, err := createTask(ctx, s.db, created.ID, nil, "workspace-bootstrap", "Skyforge workspace bootstrap", user.Username, meta); err != nil {
			log.Printf("workspace bootstrap task create: %v", err)
		} else {
			s.queueTask(task)
		}
	}

	return &created, nil
}

// SyncWorkspaceBlueprint syncs a workspace's blueprint catalog into the repo.
//
//encore:api auth method=POST path=/api/workspaces/:workspaceID/blueprint/sync
func (s *Service) SyncWorkspaceBlueprint(ctx context.Context, workspaceID string) (*BlueprintSyncResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, workspaceID)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	blueprint := strings.TrimSpace(pc.workspace.Blueprint)
	if blueprint == "" {
		blueprint = defaultBlueprintCatalog
	}

	if strings.EqualFold(blueprint, defaultBlueprintCatalog) {
		if err := ensureBlueprintCatalogRepo(s.cfg, blueprint); err != nil {
			log.Printf("ensureBlueprintCatalogRepo: %v", err)
		}
	}
	profile := &UserProfile{
		Authenticated: true,
		Username:      user.Username,
		DisplayName:   strings.TrimSpace(user.DisplayName),
		Email:         strings.TrimSpace(user.Email),
		Groups:        user.Groups,
		IsAdmin:       isAdminUser(s.cfg, user.Username),
	}
	if profile.DisplayName == "" {
		profile.DisplayName = profile.Username
	}
	if profile.Email == "" && strings.TrimSpace(s.cfg.CorpEmailDomain) != "" {
		profile.Email = fmt.Sprintf("%s@%s", profile.Username, strings.TrimSpace(s.cfg.CorpEmailDomain))
	}
	if err := ensureGiteaUserFromProfile(s.cfg, profile); err != nil {
		log.Printf("ensureGiteaUserFromProfile: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision gitea user").Err()
	}
	giteaCfg := s.cfg
	targetBranch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if targetBranch == "" {
		targetBranch = "main"
	}
	if err := syncBlueprintCatalogIntoWorkspaceRepo(s.cfg, giteaCfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, blueprint, targetBranch, pc.claims); err != nil {
		log.Printf("syncBlueprintCatalogIntoWorkspaceRepo: %v", err)
		if fallbackErr := syncBlueprintCatalogIntoWorkspaceRepo(s.cfg, s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, blueprint, targetBranch, pc.claims); fallbackErr != nil {
			log.Printf("syncBlueprintCatalogIntoWorkspaceRepo fallback: %v", fallbackErr)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync blueprint").Err()
		}
	}

	// Netlab template listing walks the repo tree via Gitea API; cache it in Redis for speed.
	// Since this sync mutates the workspace repo, invalidate any cached listings.
	invalidateNetlabTemplatesCacheForRepoBranch(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, targetBranch)

	_ = ctx
	return &BlueprintSyncResponse{Status: "ok"}, nil
}
