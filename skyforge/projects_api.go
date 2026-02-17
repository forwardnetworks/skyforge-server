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

type contextCreateContextKey string

const contextCreateInternalKey contextCreateContextKey = "allow_context_create_internal"

type UsersListParams struct {
	All string `query:"all" encore:"optional"`
}

type UsersListResponse struct {
	User     string                `json:"user"`
	Contexts []SkyforgeUserContext `json:"contexts"`
}

const defaultBlueprintCatalog = "skyforge/blueprints"

func defaultContextSlug(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	if normalized == "" {
		normalized = "user"
	}
	return slugify(fmt.Sprintf("user-%s", normalized))
}

func defaultContextName(username string) string {
	normalized := strings.TrimSpace(username)
	if normalized == "" {
		normalized = "User"
	}
	return fmt.Sprintf("%s Personal", normalized)
}

func defaultContextRepo() string {
	return "user"
}

// Legacy helper aliases; prefer context* names.
func defaultUserSlug(username string) string { return defaultContextSlug(username) }
func defaultUserName(username string) string { return defaultContextName(username) }
func defaultUserRepo() string                { return defaultContextRepo() }

func (s *Service) ensureDefaultOwnerContext(ctx context.Context, user *AuthUser) (*SkyforgeUserContext, error) {
	if user == nil {
		return nil, nil
	}
	contexts, err := s.ownerContextStore.load()
	if err != nil {
		return nil, err
	}
	baseSlug := defaultContextSlug(user.Username)
	slug := baseSlug
	for _, w := range contexts {
		if strings.EqualFold(w.CreatedBy, user.Username) && strings.EqualFold(w.Slug, baseSlug) {
			s.maybeQueueUserBootstrap(ctx, w.ID, user)
			return &w, nil
		}
		if strings.EqualFold(w.Slug, slug) && !strings.EqualFold(w.CreatedBy, user.Username) {
			slug = fmt.Sprintf("%s-%d", baseSlug, time.Now().Unix()%10000)
		}
	}
	req := &UserCreateRequest{
		Name:      defaultContextName(user.Username),
		Slug:      slug,
		Blueprint: defaultBlueprintCatalog,
	}
	internalCtx := context.WithValue(ctx, contextCreateInternalKey, true)
	created, err := s.CreateOwnerContext(internalCtx, req)
	if err != nil {
		return nil, err
	}
	if created != nil {
		s.maybeQueueUserBootstrap(ctx, created.ID, user)
	}
	return created, nil
}

func (s *Service) maybeQueueUserBootstrap(ctx context.Context, ownerID string, user *AuthUser) {
	if s == nil || s.db == nil || user == nil {
		return
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
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
	task, err := createTask(ctx, s.db, ownerID, nil, "user-bootstrap", "Skyforge user bootstrap", username, meta)
	if err != nil {
		return
	}
	s.queueTask(task)
}

func (s *Service) resolveUserForUser(ctx context.Context, user *AuthUser, ownerKey string) (*SkyforgeUserContext, error) {
	ownerKey = strings.TrimSpace(ownerKey)
	if ownerKey == "" || isPersonalOwnerKey(ownerKey) {
		userContext, err := s.ensureDefaultOwnerContext(ctx, user)
		if err != nil {
			return nil, err
		}
		if userContext == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("owner_username is required").Err()
		}
		return userContext, nil
	}
	wc, err := s.ownerContextForUser(user, ownerKey)
	if err != nil {
		return nil, err
	}
	return &wc.context, nil
}

// GetUsers returns user contexts visible to the authenticated user.
//
// Returns contexts visible to the authenticated user.
func (s *Service) GetUsers(ctx context.Context, params *UsersListParams) (*UsersListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	isAdmin := isAdminUser(s.cfg, user.Username)

	if _, err := s.ensureDefaultOwnerContext(ctx, user); err != nil {
		log.Printf("default context ensure: %v", err)
	}
	contexts, err := s.ownerContextStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user contexts").Err()
	}
	all := false
	_ = params
	if !isAdmin && !all {
		changed := false
		changedScopes := make([]SkyforgeUserContext, 0)
		for i := range contexts {
			if role, ok := syncGroupMembershipForUser(&contexts[i], claims); ok {
				changed = true
				changedScopes = append(changedScopes, contexts[i])
				log.Printf("context group sync: %s -> %s (%s)", user.Username, contexts[i].Slug, role)
			}
		}
		if changed {
			updatedAll := true
			for _, w := range changedScopes {
				if err := s.ownerContextStore.upsert(w); err != nil {
					updatedAll = false
					log.Printf("context upsert after group sync (%s): %v", w.ID, err)
				}
			}
			if updatedAll {
				for _, w := range changedScopes {
					syncGiteaCollaboratorsForOwnerContext(s.cfg, w)
				}
			}
		}
		filtered := make([]SkyforgeUserContext, 0, len(contexts))
		for _, w := range contexts {
			if ownerAccessLevelForClaims(s.cfg, w, claims) != "none" {
				filtered = append(filtered, w)
			}
		}
		contexts = filtered
	}
	if !all {
		baseSlug := defaultContextSlug(user.Username)
		personal := (*SkyforgeUserContext)(nil)
		for i := range contexts {
			if strings.EqualFold(contexts[i].CreatedBy, user.Username) && strings.EqualFold(contexts[i].Slug, baseSlug) {
				w := contexts[i]
				personal = &w
				break
			}
		}
		if personal == nil {
			for i := range contexts {
				if strings.EqualFold(contexts[i].CreatedBy, user.Username) {
					w := contexts[i]
					personal = &w
					break
				}
			}
		}
		if personal != nil {
			contexts = []SkyforgeUserContext{*personal}
		}
	}

	return &UsersListResponse{
		User:     user.Username,
		Contexts: contexts,
	}, nil
}

type UserCreateRequest struct {
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

// CreateOwnerContext provisions a new Skyforge user context.
//
// Internal-only helper used to ensure personal context exists.
func (s *Service) CreateOwnerContext(ctx context.Context, req *UserCreateRequest) (*SkyforgeUserContext, error) {
	if allow, _ := ctx.Value(contextCreateInternalKey).(bool); !allow {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("shared context management has been removed; personal user context is automatic").Err()
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
		return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer cannot be set during user context creation (configure in user settings)").Err()
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
	if slug == defaultContextSlug(user.Username) {
		repo = defaultContextRepo()
	}
	terraformStateKey := fmt.Sprintf("tf-%s/primary.tfstate", slug)
	artifactsBucket := storage.StorageBucketName

	contexts, err := s.ownerContextStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user contexts").Err()
	}
	for _, existing := range contexts {
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
	// Provisioning the Gitea user is a best-effort side-effect. Context creation
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
	// Context creation should not be blocked on provisioning downstream tooling.
	// Gitea provisioning/sync is best-effort and can be retried via periodic user/context sync.
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

	created := SkyforgeUserContext{
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
	if err := s.ownerContextStore.upsert(created); err != nil {
		log.Printf("context upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist user context").Err()
	}
	if s.db != nil {
		_ = notifyUsersUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if _, err := createNotification(
			ctx,
			s.db,
			user.Username,
			fmt.Sprintf("Personal context created: %s", created.Name),
			fmt.Sprintf("Skyforge provisioned user context %s (%s).", created.Name, created.Slug),
			"SYSTEM",
			"user-contexts",
			created.ID,
			"low",
		); err != nil {
			log.Printf("create notification (context): %v", err)
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
			"context.create",
			created.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", created.Slug, created.GiteaOwner, created.GiteaRepo),
		)
	}
	syncGiteaCollaboratorsForOwnerContext(giteaCfg, created)

	// Offload repo seeding + blueprint sync to the task queue for durability/retries.
	// Context creation should succeed even if downstream provisioning is temporarily unavailable.
	if s.db != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		meta, err := toJSONMap(map[string]any{
			"dedupeKey": fmt.Sprintf("context-bootstrap:%s", strings.TrimSpace(created.ID)),
			"spec":      map[string]any{},
		})
		if err != nil {
			log.Printf("context bootstrap meta encode: %v", err)
		} else if task, err := createTask(ctx, s.db, created.ID, nil, skyforgecore.TaskTypeContextBootstrap, "Skyforge context bootstrap", user.Username, meta); err != nil {
			log.Printf("context bootstrap task create: %v", err)
		} else {
			s.queueTask(task)
		}
	}

	return &created, nil
}

// SyncUserBlueprint syncs a user context's blueprint catalog into the repo.
//
// Legacy sync route removed.
func (s *Service) SyncUserBlueprint(ctx context.Context, ownerID string) (*BlueprintSyncResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, ownerID)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	blueprint := strings.TrimSpace(pc.context.Blueprint)
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
	targetBranch := strings.TrimSpace(pc.context.DefaultBranch)
	if targetBranch == "" {
		targetBranch = "main"
	}
	if err := syncBlueprintCatalogIntoUserRepo(s.cfg, giteaCfg, pc.context.GiteaOwner, pc.context.GiteaRepo, blueprint, targetBranch, pc.claims); err != nil {
		log.Printf("syncBlueprintCatalogIntoUserRepo: %v", err)
		if fallbackErr := syncBlueprintCatalogIntoUserRepo(s.cfg, s.cfg, pc.context.GiteaOwner, pc.context.GiteaRepo, blueprint, targetBranch, pc.claims); fallbackErr != nil {
			log.Printf("syncBlueprintCatalogIntoUserRepo fallback: %v", fallbackErr)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync blueprint").Err()
		}
	}

	// Netlab template listing walks the repo tree via Gitea API; cache it in Redis for speed.
	// Since this sync mutates the context repo, invalidate any cached listings.
	invalidateNetlabTemplatesCacheForRepoBranch(s.cfg, pc.context.GiteaOwner, pc.context.GiteaRepo, targetBranch)

	_ = ctx
	return &BlueprintSyncResponse{Status: "ok"}, nil
}
