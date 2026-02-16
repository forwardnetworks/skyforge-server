package skyforge

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"encore.dev/beta/errs"
)

var errOwnerNotFound = errors.New("user context not found")
var ownerLegacyKeyWarned sync.Map

func ownerStrictModeEnabled() bool {
	return true
}

func trackOwnerRouteUsage(ownerKey string) (legacy bool, normalized string) {
	normalized = strings.TrimSpace(ownerKey)
	if normalized == "" {
		userRouteUsageTotal.With(userRouteUsageLabels{Mode: "personal_empty"}).Add(1)
		return false, "me"
	}
	if isPersonalOwnerKey(normalized) {
		userRouteUsageTotal.With(userRouteUsageLabels{Mode: "personal_alias"}).Add(1)
		return false, normalized
	}
	userRouteUsageTotal.With(userRouteUsageLabels{Mode: "legacy_key"}).Add(1)
	return true, normalized
}

func warnOwnerLegacyKeyOnce(ownerKey string) {
	key := strings.ToLower(strings.TrimSpace(ownerKey))
	if key == "" {
		return
	}
	if _, loaded := ownerLegacyKeyWarned.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	log.Printf("legacy owner route key %q used; only personal per-user access is allowed", ownerKey)
}

func (s *Service) loadOwnerContextByKey(ownerKey string) ([]SkyforgeUserContext, int, SkyforgeUserContext, error) {
	ownerKey = strings.TrimSpace(ownerKey)
	if ownerKey == "" {
		return nil, -1, SkyforgeUserContext{}, errors.New("owner username is required")
	}
	scopes, err := s.scopeStore.load()
	if err != nil {
		return nil, -1, SkyforgeUserContext{}, err
	}
	for i, w := range scopes {
		if w.ID == ownerKey || w.Slug == ownerKey {
			return scopes, i, w, nil
		}
	}
	return scopes, -1, SkyforgeUserContext{}, errOwnerNotFound
}

type ownerContext struct {
	context      SkyforgeUserContext
	access       string
	claims       *SessionClaims
	userSettings *UserSettingsResponse
}

func isPersonalOwnerKey(scopeKey string) bool {
	key := strings.ToLower(strings.TrimSpace(scopeKey))
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

func (s *Service) resolveOwnerKeyForClaims(claims *SessionClaims, ownerKey string) (string, error) {
	legacy, normalized := trackOwnerRouteUsage(ownerKey)
	ownerKey = normalized
	if legacy {
		warnOwnerLegacyKeyOnce(ownerKey)
		userRouteRejectedTotal.With(userRouteUsageLabels{Mode: "legacy_key"}).Add(1)
		return "", errs.B().Code(errs.FailedPrecondition).Msg("only personal per-user access is supported").Err()
	}
	if !isPersonalOwnerKey(ownerKey) {
		userRouteRejectedTotal.With(userRouteUsageLabels{Mode: "legacy_key"}).Add(1)
		return "", errs.B().Code(errs.FailedPrecondition).Msg("only personal per-user access is supported").Err()
	}
	user := authUserFromClaims(claims, s.cfg)
	if user == nil {
		return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	ctxEnsure, cancelEnsure := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelEnsure()
	def, err := s.ensureDefaultOwnerContext(ctxEnsure, user)
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("failed to resolve personal user context").Err()
	}
	if def == nil || strings.TrimSpace(def.ID) == "" {
		return "", errs.B().Code(errs.NotFound).Msg("personal user context not found").Err()
	}
	return strings.TrimSpace(def.ID), nil
}

func (s *Service) ownerContextForUser(user *AuthUser, ownerKey string) (*ownerContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	legacy, normalized := trackOwnerRouteUsage(ownerKey)
	ownerKey = normalized
	if legacy {
		warnOwnerLegacyKeyOnce(ownerKey)
		userRouteRejectedTotal.With(userRouteUsageLabels{Mode: "legacy_key"}).Add(1)
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("only personal per-user access is supported").Err()
	}
	if !isPersonalOwnerKey(ownerKey) {
		userRouteRejectedTotal.With(userRouteUsageLabels{Mode: "legacy_key"}).Add(1)
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("only personal per-user access is supported").Err()
	}
	claims := claimsFromAuthUser(user)
	ctxEnsure, cancelEnsure := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelEnsure()
	def, err := s.ensureDefaultOwnerContext(ctxEnsure, user)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to resolve personal user context").Err()
	}
	if def == nil || strings.TrimSpace(def.ID) == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("personal user context not found").Err()
	}
	ownerKey = def.ID
	_, _, scope, err := s.loadOwnerContextByKey(ownerKey)
	if err != nil {
		if errors.Is(err, errOwnerNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("user context not found").Err()
		}
		if err.Error() == "owner username is required" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user contexts").Err()
	}
	access := ownerAccessLevelForClaims(s.cfg, scope, claims)
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
	return &ownerContext{
		context:      scope,
		access:       access,
		claims:       claims,
		userSettings: userSettings,
	}, nil
}
