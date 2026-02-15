package skyforge

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"encore.dev/beta/errs"
)

var errWorkspaceNotFound = errors.New("workspace not found")
var workspaceLegacyKeyWarned sync.Map

func workspaceStrictModeEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("SKYFORGE_WORKSPACE_ROUTES_STRICT"))
	return strings.EqualFold(raw, "true") || raw == "1" || strings.EqualFold(raw, "yes")
}

func trackWorkspaceRouteUsage(workspaceKey string) (legacy bool, normalized string) {
	normalized = strings.TrimSpace(workspaceKey)
	if normalized == "" {
		workspaceRouteUsageTotal.With(workspaceRouteUsageLabels{Mode: "personal_empty"}).Add(1)
		return false, "me"
	}
	if isPersonalWorkspaceKey(normalized) {
		workspaceRouteUsageTotal.With(workspaceRouteUsageLabels{Mode: "personal_alias"}).Add(1)
		return false, normalized
	}
	workspaceRouteUsageTotal.With(workspaceRouteUsageLabels{Mode: "legacy_key"}).Add(1)
	return true, normalized
}

func warnWorkspaceLegacyKeyOnce(workspaceKey string) {
	key := strings.ToLower(strings.TrimSpace(workspaceKey))
	if key == "" {
		return
	}
	if _, loaded := workspaceLegacyKeyWarned.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	log.Printf("workspace route deprecation: legacy workspace key %q used; migrate to /api/user/workspace/*", workspaceKey)
}

func (s *Service) loadWorkspaceByKey(workspaceKey string) ([]SkyforgeWorkspace, int, SkyforgeWorkspace, error) {
	workspaceKey = strings.TrimSpace(workspaceKey)
	if workspaceKey == "" {
		return nil, -1, SkyforgeWorkspace{}, errors.New("workspace id is required")
	}
	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, -1, SkyforgeWorkspace{}, err
	}
	for i, w := range workspaces {
		if w.ID == workspaceKey || w.Slug == workspaceKey {
			return workspaces, i, w, nil
		}
	}
	return workspaces, -1, SkyforgeWorkspace{}, errWorkspaceNotFound
}

type workspaceContext struct {
	workspaces   []SkyforgeWorkspace
	idx          int
	workspace    SkyforgeWorkspace
	access       string
	claims       *SessionClaims
	userSettings *UserSettingsResponse
}

func isPersonalWorkspaceKey(workspaceKey string) bool {
	key := strings.ToLower(strings.TrimSpace(workspaceKey))
	return key == "me" || key == "self" || key == "personal"
}

func authUserFromClaims(claims *SessionClaims, cfg Config) *AuthUser {
	if claims == nil {
		return nil
	}
	username := strings.ToLower(strings.TrimSpace(claims.Username))
	if username == "" {
		return nil
	}
	return &AuthUser{
		Username:      username,
		DisplayName:   strings.TrimSpace(claims.DisplayName),
		Email:         strings.TrimSpace(claims.Email),
		Groups:        claims.Groups,
		ActorUsername: strings.ToLower(strings.TrimSpace(claims.ActorUsername)),
		Impersonating: isImpersonating(claims),
		IsAdmin:       isAdminUser(cfg, adminUsernameForClaims(claims)),
		SelectedRole:  "",
	}
}

func (s *Service) resolveWorkspaceKeyForClaims(claims *SessionClaims, workspaceKey string) (string, error) {
	legacy, normalized := trackWorkspaceRouteUsage(workspaceKey)
	workspaceKey = normalized
	if legacy {
		warnWorkspaceLegacyKeyOnce(workspaceKey)
		if workspaceStrictModeEnabled() {
			workspaceRouteRejectedTotal.With(workspaceRouteUsageLabels{Mode: "legacy_key"}).Add(1)
			return "", errs.B().Code(errs.FailedPrecondition).Msg("workspace-scoped routes are deprecated; use /api/user/workspace/*").Err()
		}
	}
	if !isPersonalWorkspaceKey(workspaceKey) {
		return workspaceKey, nil
	}
	user := authUserFromClaims(claims, s.cfg)
	if user == nil {
		return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	ctxEnsure, cancelEnsure := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelEnsure()
	def, err := s.ensureDefaultWorkspace(ctxEnsure, user)
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("failed to resolve personal scope").Err()
	}
	if def == nil || strings.TrimSpace(def.ID) == "" {
		return "", errs.B().Code(errs.NotFound).Msg("personal scope not found").Err()
	}
	return strings.TrimSpace(def.ID), nil
}

func (s *Service) workspaceContextForUser(user *AuthUser, workspaceKey string) (*workspaceContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	legacy, normalized := trackWorkspaceRouteUsage(workspaceKey)
	workspaceKey = normalized
	if legacy {
		warnWorkspaceLegacyKeyOnce(workspaceKey)
		if workspaceStrictModeEnabled() {
			workspaceRouteRejectedTotal.With(workspaceRouteUsageLabels{Mode: "legacy_key"}).Add(1)
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("workspace-scoped routes are deprecated; use /api/user/workspace/*").Err()
		}
	}
	claims := claimsFromAuthUser(user)
	if isPersonalWorkspaceKey(workspaceKey) {
		ctxEnsure, cancelEnsure := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelEnsure()
		def, err := s.ensureDefaultWorkspace(ctxEnsure, user)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to resolve personal scope").Err()
		}
		if def == nil || strings.TrimSpace(def.ID) == "" {
			return nil, errs.B().Code(errs.NotFound).Msg("personal scope not found").Err()
		}
		workspaceKey = def.ID
	}
	workspaces, idx, workspace, err := s.loadWorkspaceByKey(workspaceKey)
	if err != nil {
		if errors.Is(err, errWorkspaceNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("workspace not found").Err()
		}
		if err.Error() == "workspace id is required" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	access := workspaceAccessLevelForClaims(s.cfg, workspace, claims)
	if access == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	var userSettings *UserSettingsResponse
	if s != nil && s.db != nil {
		ctxSettings, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if rec, err := getUserSettings(ctxSettings, s.db, claims.Username); err == nil && rec != nil {
			var env []UserEnvVar
			if strings.TrimSpace(rec.DefaultEnvJSON) != "" {
				_ = json.Unmarshal([]byte(rec.DefaultEnvJSON), &env)
			}
			var repos []ExternalTemplateRepo
			if strings.TrimSpace(rec.ExternalTemplateReposJSON) != "" {
				_ = json.Unmarshal([]byte(rec.ExternalTemplateReposJSON), &repos)
			}
			userSettings = &UserSettingsResponse{
				DefaultForwardCollectorConfigID: strings.TrimSpace(rec.DefaultForwardCollectorConfig),
				DefaultEnv:                      env,
				ExternalTemplateRepos:           repos,
				UpdatedAt:                       rec.UpdatedAt.UTC().Format(time.RFC3339),
			}
		}
	}
	return &workspaceContext{
		workspaces:   workspaces,
		idx:          idx,
		workspace:    workspace,
		access:       access,
		claims:       claims,
		userSettings: userSettings,
	}, nil
}
