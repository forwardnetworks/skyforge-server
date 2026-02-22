package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"encore.app/internal/skyforgecore"
	"encore.app/storage"
)

type UserScopesListParams struct {
	All string `query:"all" encore:"optional"`
}

type UserScopesListResponse struct {
	User       string      `json:"user"`
	UserScopes []UserScope `json:"userScopes"`
}

const defaultBlueprintCatalog = "skyforge/blueprints"

func defaultUserScopeSlug(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	if normalized == "" {
		normalized = "user"
	}
	return slugify(fmt.Sprintf("user-%s", normalized))
}

func defaultUserScopeName(username string) string {
	normalized := strings.TrimSpace(username)
	if normalized == "" {
		normalized = "User"
	}
	return normalized
}

func defaultUserScopeRepo() string {
	return "user"
}

func (s *Service) ensureDefaultUserScope(ctx context.Context, user *AuthUser) (*UserScope, error) {
	if user == nil {
		return nil, nil
	}
	userScopes, err := s.userScopeStore.load()
	if err != nil {
		return nil, err
	}
	baseSlug := defaultUserScopeSlug(user.Username)
	slug := baseSlug
	for _, w := range userScopes {
		if strings.EqualFold(w.CreatedBy, user.Username) && strings.EqualFold(w.Slug, baseSlug) {
			s.maybeQueueUserBootstrap(ctx, w.ID, user)
			return &w, nil
		}
		if strings.EqualFold(w.Slug, slug) && !strings.EqualFold(w.CreatedBy, user.Username) {
			slug = fmt.Sprintf("%s-%d", baseSlug, time.Now().Unix()%10000)
		}
	}
	req := &UserScopeCreateRequest{
		Name:      defaultUserScopeName(user.Username),
		Slug:      slug,
		Blueprint: defaultBlueprintCatalog,
	}
	created, err := s.CreateUserScope(ctx, req)
	if err != nil {
		return nil, err
	}
	if created != nil {
		s.maybeQueueUserBootstrap(ctx, created.ID, user)
	}
	return created, nil
}

func (s *Service) maybeQueueUserBootstrap(ctx context.Context, userScopeID string, user *AuthUser) {
	if s == nil || s.db == nil || user == nil {
		return
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
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
	task, err := createTask(ctx, s.db, userScopeID, nil, "user-bootstrap", "Skyforge user bootstrap", username, meta)
	if err != nil {
		return
	}
	s.queueTask(task)
}

func (s *Service) resolveUserScopeForUser(ctx context.Context, user *AuthUser, userScopeKey string) (*UserScope, error) {
	userScopeKey = strings.TrimSpace(userScopeKey)
	if userScopeKey == "" {
		userScope, err := s.ensureDefaultUserScope(ctx, user)
		if err != nil {
			return nil, err
		}
		if userScope == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("user_id is required").Err()
		}
		return userScope, nil
	}
	wc, err := s.userContextForUser(user, userScopeKey)
	if err != nil {
		return nil, err
	}
	return &wc.userScope, nil
}

// GetUserScopes returns user scopes visible to the authenticated user.
//
//encore:api auth method=GET path=/api/users tag:list-user-scopes
func (s *Service) GetUserScopes(ctx context.Context, params *UserScopesListParams) (*UserScopesListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	isAdmin := isAdminUser(s.cfg, user.Username)

	if _, err := s.ensureDefaultUserScope(ctx, user); err != nil {
		log.Printf("default user scope ensure: %v", err)
	}
	userScopes, err := s.userScopeStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user scopes").Err()
	}
	all := params != nil && strings.EqualFold(strings.TrimSpace(params.All), "true")
	if !isAdmin && all {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("admin access required for all user scopes").Err()
	}
	if !isAdmin && !all {
		changed := false
		changedUserScopes := make([]UserScope, 0)
		for i := range userScopes {
			if role, ok := syncGroupMembershipForUser(&userScopes[i], claims); ok {
				changed = true
				changedUserScopes = append(changedUserScopes, userScopes[i])
				log.Printf("user-scope group sync: %s -> %s (%s)", user.Username, userScopes[i].Slug, role)
			}
		}
		if changed {
			updatedAll := true
			for _, w := range changedUserScopes {
				if err := s.userScopeStore.upsert(w); err != nil {
					updatedAll = false
					log.Printf("user-scope upsert after group sync (%s): %v", w.ID, err)
				}
			}
			if updatedAll {
				for _, w := range changedUserScopes {
					syncGiteaCollaboratorsForUserScope(s.cfg, w)
				}
			}
		}
		filtered := make([]UserScope, 0, len(userScopes))
		for _, w := range userScopes {
			if userScopeAccessLevelForClaims(s.cfg, w, claims) != "none" {
				filtered = append(filtered, w)
			}
		}
		userScopes = filtered
	}

	_ = ctx
	return &UserScopesListResponse{
		User:       user.Username,
		UserScopes: userScopes,
	}, nil
}

type UserScopeCreateRequest struct {
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

// CreateUserScope provisions a new Skyforge user scope.
//
//encore:api auth method=POST path=/api/users
func (s *Service) CreateUserScope(ctx context.Context, req *UserScopeCreateRequest) (*UserScope, error) {
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
		return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer cannot be set at user-scope creation (configure in user-scope settings)").Err()
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
	if slug == defaultUserScopeSlug(user.Username) {
		repo = defaultUserScopeRepo()
	}
	terraformStateKey := fmt.Sprintf("tf-%s/primary.tfstate", slug)
	artifactsBucket := storage.StorageBucketName

	userScopes, err := s.userScopeStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user scopes").Err()
	}
	for _, existing := range userScopes {
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
	// Provisioning the Gitea user is a best-effort side-effect. User-scope creation
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
	// User-scope creation should not be blocked on provisioning downstream tooling.
	// Gitea provisioning/sync is best-effort and can be retried via user-scope sync.
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

	created := UserScope{
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
	if err := s.userScopeStore.upsert(created); err != nil {
		log.Printf("user-scope upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist user scope").Err()
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
			fmt.Sprintf("User scope created: %s", created.Name),
			fmt.Sprintf("Skyforge provisioned user scope %s (%s).", created.Name, created.Slug),
			"SYSTEM",
			"user-scopes",
			created.ID,
			"low",
		); err != nil {
			log.Printf("create notification (user-scope): %v", err)
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
			"user-scope.create",
			created.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", created.Slug, created.GiteaOwner, created.GiteaRepo),
		)
	}
	syncGiteaCollaboratorsForUserScope(giteaCfg, created)

	// Offload repo seeding + blueprint sync to the task queue for durability/retries.
	// User-scope creation should succeed even if downstream provisioning is temporarily unavailable.
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		meta, err := toJSONMap(map[string]any{
			"dedupeKey": fmt.Sprintf("user-scope-bootstrap:%s", strings.TrimSpace(created.ID)),
			"spec":      map[string]any{},
		})
		if err != nil {
			log.Printf("user-scope bootstrap meta encode: %v", err)
		} else if task, err := createTask(ctx, s.db, created.ID, nil, skyforgecore.TaskTypeUserScopeBootstrap, "Skyforge user-scope bootstrap", user.Username, meta); err != nil {
			log.Printf("user-scope bootstrap task create: %v", err)
		} else {
			s.queueTask(task)
		}
	}

	return &created, nil
}

// SyncUserBlueprint syncs a user's blueprint catalog into the repo.
//
//encore:api auth method=POST path=/api/users/:userID/blueprint/sync
func (s *Service) SyncUserBlueprint(ctx context.Context, userID string) (*BlueprintSyncResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, userID)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	blueprint := strings.TrimSpace(pc.userScope.Blueprint)
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
	targetBranch := strings.TrimSpace(pc.userScope.DefaultBranch)
	if targetBranch == "" {
		targetBranch = "main"
	}
	if err := syncBlueprintCatalogIntoWorkspaceRepo(s.cfg, giteaCfg, pc.userScope.GiteaOwner, pc.userScope.GiteaRepo, blueprint, targetBranch, pc.claims); err != nil {
		log.Printf("syncBlueprintCatalogIntoWorkspaceRepo: %v", err)
		if fallbackErr := syncBlueprintCatalogIntoWorkspaceRepo(s.cfg, s.cfg, pc.userScope.GiteaOwner, pc.userScope.GiteaRepo, blueprint, targetBranch, pc.claims); fallbackErr != nil {
			log.Printf("syncBlueprintCatalogIntoWorkspaceRepo fallback: %v", fallbackErr)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync blueprint").Err()
		}
	}

	// Netlab template listing walks the repo tree via Gitea API; cache it in Redis for speed.
	// Since this sync mutates the user-scope repo, invalidate any cached listings.
	invalidateNetlabTemplatesCacheForRepoBranch(s.cfg, pc.userScope.GiteaOwner, pc.userScope.GiteaRepo, targetBranch)

	_ = ctx
	return &BlueprintSyncResponse{Status: "ok"}, nil
}
