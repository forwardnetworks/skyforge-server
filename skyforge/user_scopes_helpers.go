package skyforge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

var errUserScopeNotFound = errors.New("user scope not found")

func (s *Service) loadUserScopeByKey(userScopeKey string) ([]UserScope, int, UserScope, error) {
	userScopeKey = strings.TrimSpace(userScopeKey)
	if userScopeKey == "" {
		return nil, -1, UserScope{}, errors.New("user id is required")
	}
	userScopes, err := s.userScopeStore.load()
	if err != nil {
		return nil, -1, UserScope{}, err
	}
	for i, w := range userScopes {
		if w.ID == userScopeKey || w.Slug == userScopeKey {
			return userScopes, i, w, nil
		}
	}
	return userScopes, -1, UserScope{}, errUserScopeNotFound
}

type userContext struct {
	userScopes   []UserScope
	idx          int
	userScope    UserScope
	access       string
	claims       *SessionClaims
	userSettings *UserSettingsResponse
}

func (s *Service) userContextForUser(user *AuthUser, userScopeKey string) (*userContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	claims := claimsFromAuthUser(user)
	userScopes, idx, userScope, err := s.loadUserScopeByKey(userScopeKey)
	if err != nil {
		if errors.Is(err, errUserScopeNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("user scope not found").Err()
		}
		if err.Error() == "user id is required" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user scopes").Err()
	}
	access := userScopeAccessLevelForClaims(s.cfg, userScope, claims)
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
	return &userContext{
		userScopes:   userScopes,
		idx:          idx,
		userScope:    userScope,
		access:       access,
		claims:       claims,
		userSettings: userSettings,
	}, nil
}
