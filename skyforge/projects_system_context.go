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
func (s *Service) systemUserContext(ctx context.Context, workspaceKey string, username string) (*userContext, error) {
	_ = ctx
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	workspaceKey = strings.TrimSpace(workspaceKey)
	if workspaceKey == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("workspace id is required").Err()
	}
	workspaces, idx, workspace, err := s.loadWorkspaceByKey(workspaceKey)
	if err != nil {
		if errors.Is(err, errWorkspaceNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("workspace not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = strings.TrimSpace(workspace.CreatedBy)
	}
	claims := &SessionClaims{
		Username:    username,
		DisplayName: username,
		Email:       "",
		Groups:      nil,
	}
	return &userContext{
		workspaces: workspaces,
		idx:        idx,
		workspace:  workspace,
		access:     "owner",
		claims:     claims,
	}, nil
}
