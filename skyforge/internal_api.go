package skyforge

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type InternalProjectsExportParams struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

type InternalProjectsExportResponse struct {
	Projects   []SkyforgeProject `json:"projects"`
	Users      []string          `json:"users"`
	Timestamp  string            `json:"timestamp"`
	StateStore string            `json:"stateStore"`
}

// ExportProjects returns project and user state for internal tooling.
//
//encore:api public method=GET path=/api/internal/projects-export
func (s *Service) ExportProjects(ctx context.Context, params *InternalProjectsExportParams) (*InternalProjectsExportResponse, error) {
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
	projects, err := s.projectStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	users, err := s.userStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load users").Err()
	}
	_ = ctx
	return &InternalProjectsExportResponse{
		Projects:   projects,
		Users:      users,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		StateStore: s.cfg.StateBackend,
	}, nil
}

// ExportProjectsV1 returns project and user state for internal tooling (v1 alias).
//
//encore:api public method=GET path=/api/v1/internal/projects-export
func (s *Service) ExportProjectsV1(ctx context.Context, params *InternalProjectsExportParams) (*InternalProjectsExportResponse, error) {
	return s.ExportProjects(ctx, params)
}
