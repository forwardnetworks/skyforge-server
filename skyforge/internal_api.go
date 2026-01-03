package skyforge

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type InternalWorkspacesExportParams struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

type InternalWorkspacesExportResponse struct {
	Workspaces []SkyforgeWorkspace `json:"workspaces"`
	Users      []string            `json:"users"`
	Timestamp  string              `json:"timestamp"`
	StateStore string              `json:"stateStore"`
}

// ExportWorkspaces returns workspace and user state for internal tooling.
//
//encore:api public method=GET path=/api/internal/workspaces-export
func (s *Service) ExportWorkspaces(ctx context.Context, params *InternalWorkspacesExportParams) (*InternalWorkspacesExportResponse, error) {
	if strings.TrimSpace(s.cfg.InternalToken) == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("not found").Err()
	}
	token := ""
	if params != nil {
		token = strings.TrimSpace(params.Token)
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.InternalToken)) != 1 {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	users, err := s.userStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load users").Err()
	}
	_ = ctx
	return &InternalWorkspacesExportResponse{
		Workspaces: workspaces,
		Users:      users,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		StateStore: s.cfg.StateBackend,
	}, nil
}
