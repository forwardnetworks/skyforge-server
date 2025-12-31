package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
)

type TemplatesParams struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Cookie    string `header:"Cookie"`
}

type TemplatesResponse struct {
	User      string            `json:"user"`
	ProjectID string            `json:"projectId"`
	Templates []TemplateSummary `json:"templates"`
}

// GetTemplates returns available templates for a project.
//
//encore:api public method=GET path=/api/templates
func (s *Service) GetTemplates(ctx context.Context, params *TemplatesParams) (*TemplatesResponse, error) {
	projectID := ""
	if params != nil {
		projectID = strings.TrimSpace(params.ProjectID)
	}

	claims := claimsFromCookie(s.sessionManager, func() string {
		if params == nil {
			return ""
		}
		return params.Cookie
	}())
	if claims == nil {
		return &TemplatesResponse{
			User:      "",
			ProjectID: projectID,
			Templates: []TemplateSummary{},
		}, nil
	}
	if projectID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}

	projects, err := s.projectStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	if p := findProjectByKey(projects, projectID); p != nil {
		if projectAccessLevel(s.cfg, *p, claims.Username) == "none" {
			return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
		}
	} else {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project not found").Err()
	}

	_ = ctx
	return &TemplatesResponse{
		User:      claims.Username,
		ProjectID: projectID,
		Templates: []TemplateSummary{},
	}, nil
}
