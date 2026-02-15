package skyforge

import (
	"context"
	"strings"
)

type TemplatesParams struct {
	WorkspaceID string `query:"workspace_id" encore:"optional"`
	Cookie      string `header:"Cookie"`
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
		workspaceID = "me"
	}
	wk, err := s.resolveWorkspaceKeyForClaims(claims, workspaceID)
	if err != nil {
		return nil, err
	}
	workspaceID = wk

	_ = ctx
	return &TemplatesResponse{
		User:        claims.Username,
		WorkspaceID: workspaceID,
		Templates:   []TemplateSummary{},
	}, nil
}
