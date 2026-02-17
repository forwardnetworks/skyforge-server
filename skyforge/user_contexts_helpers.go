package skyforge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

var errUserContextNotFound = errors.New("user context not found")

func (s *Service) loadUserContextByKey(userContextKey string) ([]SkyforgeWorkspace, int, SkyforgeWorkspace, error) {
	userContextKey = strings.TrimSpace(userContextKey)
	if userContextKey == "" {
		return nil, -1, SkyforgeWorkspace{}, errors.New("user context id is required")
	}
	userContexts, err := s.userContextStore.load()
	if err != nil {
		return nil, -1, SkyforgeWorkspace{}, err
	}
	for i, w := range userContexts {
		if w.ID == userContextKey || w.Slug == userContextKey {
			return userContexts, i, w, nil
		}
	}
	return userContexts, -1, SkyforgeWorkspace{}, errUserContextNotFound
}

type userContext struct {
	userContexts []SkyforgeWorkspace
	idx          int
	userContext  SkyforgeWorkspace
	access       string
	claims       *SessionClaims
	userSettings *UserSettingsResponse
}

func (s *Service) userContextForUser(user *AuthUser, userContextKey string) (*userContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	claims := claimsFromAuthUser(user)
	userContexts, idx, userContextRec, err := s.loadUserContextByKey(userContextKey)
	if err != nil {
		if errors.Is(err, errUserContextNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("user context not found").Err()
		}
		if err.Error() == "user context id is required" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user contexts").Err()
	}
	access := userContextAccessLevelForClaims(s.cfg, userContextRec, claims)
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
		userContexts: userContexts,
		idx:          idx,
		userContext:  userContextRec,
		access:       access,
		claims:       claims,
		userSettings: userSettings,
	}, nil
}

func (s *Service) userContextForCurrentUser(ctx context.Context, user *AuthUser) (*userContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	ws, err := s.resolveUserContextForUser(ctx, user, "")
	if err != nil {
		return nil, err
	}
	if ws == nil || strings.TrimSpace(ws.ID) == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("user context not found").Err()
	}
	return s.userContextForUser(user, ws.ID)
}
