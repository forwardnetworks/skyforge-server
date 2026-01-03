package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
)

type TemplatesParams struct {
	WorkspaceID string `query:"workspace_id" encore:"optional"`
	Cookie     string `header:"Cookie"`
}

type TemplatesResponse struct {
	User        string            `json:"user"`
	WorkspaceID string            `json:"workspaceId"`
	Templates   []TemplateSummary `json:"templates"`
}

// GetTemplates returns available templates for a workspace.
//
//encore:api public method=GET path=/api/templates
func (s *Service) GetTemplates(ctx context.Context, params *TemplatesParams) (*TemplatesResponse, error) {
	workspaceID := ""
	if params != nil {
		workspaceID = strings.TrimSpace(params.WorkspaceID)
	}

	claims := claimsFromCookie(s.sessionManager, func() string {
		if params == nil {
			return ""
		}
		return params.Cookie
	}())
	if claims == nil {
		return &TemplatesResponse{
			User:        "",
			WorkspaceID: workspaceID,
			Templates:   []TemplateSummary{},
		}, nil
	}
	if workspaceID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("workspace_id is required").Err()
	}

	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	if w := findWorkspaceByKey(workspaces, workspaceID); w != nil {
		if workspaceAccessLevel(s.cfg, *w, claims.Username) == "none" {
			return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
		}
	} else {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("workspace not found").Err()
	}

	_ = ctx
	return &TemplatesResponse{
		User:        claims.Username,
		WorkspaceID: workspaceID,
		Templates:   []TemplateSummary{},
	}, nil
}
