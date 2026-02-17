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
func (s *Service) systemUserContext(ctx context.Context, userContextKey string, username string) (*userContext, error) {
	_ = ctx
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	userContextKey = strings.TrimSpace(userContextKey)
	if userContextKey == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("userContextId is required").Err()
	}
	userContexts, idx, userContextRec, err := s.loadUserContextByKey(userContextKey)
	if err != nil {
		if errors.Is(err, errUserContextNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("user context not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user contexts").Err()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = strings.TrimSpace(userContextRec.CreatedBy)
	}
	claims := &SessionClaims{
		Username:    username,
		DisplayName: username,
		Email:       "",
		Groups:      nil,
	}
	return &userContext{
		userContexts: userContexts,
		idx:          idx,
		userContext:  userContextRec,
		access:       "owner",
		claims:       claims,
	}, nil
}
