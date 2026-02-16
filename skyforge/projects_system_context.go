package skyforge

import (
	"context"
	"errors"
	"strings"

	"encore.dev/beta/errs"
)

// systemUserContext returns a ownerContext without enforcing user RBAC.
// Background task execution uses this because it doesn't have an incoming request
// with an Encore auth context. The task row itself is only created via authenticated
// endpoints, so the authorization boundary remains the API layer.
func (s *Service) systemUserContext(ctx context.Context, scopeKey string, username string) (*ownerContext, error) {
	_ = ctx
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	scopeKey = strings.TrimSpace(scopeKey)
	if scopeKey == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("owner username is required").Err()
	}
	_, _, contextRec, err := s.loadOwnerContextByKey(scopeKey)
	if err != nil {
		if errors.Is(err, errOwnerNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("user context not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user contexts").Err()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = strings.TrimSpace(contextRec.CreatedBy)
	}
	claims := &SessionClaims{
		Username:    username,
		DisplayName: username,
		Email:       "",
		Groups:      nil,
	}
	return &ownerContext{
		context: contextRec,
		access:  "owner",
		claims:  claims,
	}, nil
}
