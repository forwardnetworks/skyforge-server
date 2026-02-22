package skyforge

import (
	"context"
	"errors"
	"strings"

	"encore.dev/beta/errs"
)

// systemUserContext returns a userContext without enforcing user RBAC.
// Background task execution uses this because it doesn't have an incoming request
// with an Encore auth context. The task row itself is only created via authenticated
// endpoints, so the authorization boundary remains the API layer.
func (s *Service) systemUserContext(ctx context.Context, userScopeKey string, username string) (*userContext, error) {
	_ = ctx
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	userScopeKey = strings.TrimSpace(userScopeKey)
	if userScopeKey == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user id is required").Err()
	}
	userScopes, idx, userScope, err := s.loadUserScopeByKey(userScopeKey)
	if err != nil {
		if errors.Is(err, errUserScopeNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("user scope not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user scopes").Err()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = strings.TrimSpace(userScope.CreatedBy)
	}
	claims := &SessionClaims{
		Username:    username,
		DisplayName: username,
		Email:       "",
		Groups:      nil,
	}
	return &userContext{
		userScopes: userScopes,
		idx:        idx,
		userScope:  userScope,
		access:     "owner",
		claims:     claims,
	}, nil
}
