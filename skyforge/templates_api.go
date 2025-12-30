package skyforge

import (
	"context"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

type TemplatesParams struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Cookie    string `header:"Cookie"`
}

type TemplatesResponse struct {
	User      string            `json:"user"`
	ProjectID int               `json:"project_id"`
	Templates []TemplateSummary `json:"templates"`
}

// GetTemplates returns available templates for a project.
//
//encore:api public method=GET path=/api/templates
func (s *Service) GetTemplates(ctx context.Context, params *TemplatesParams) (*TemplatesResponse, error) {
	projectID := s.cfg.DefaultProject
	if params != nil {
		if projectParam := strings.TrimSpace(params.ProjectID); projectParam != "" {
			if v, err := strconv.Atoi(projectParam); err == nil {
				projectID = v
			} else if strings.TrimSpace(params.Cookie) != "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid project_id").Err()
			}
		}
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
	if projectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}

	projects, err := s.projectStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	if p := findProjectBySemaphoreID(projects, projectID); p != nil {
		if projectAccessLevel(s.cfg, *p, claims.Username) == "none" {
			return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
		}
	} else if !isAdminUser(s.cfg, claims.Username) && projectID != s.cfg.DefaultProject {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	templates, err := fetchSemaphoreTemplates(s.cfg, projectID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query semaphore").Err()
	}
	_ = ctx
	return &TemplatesResponse{
		User:      claims.Username,
		ProjectID: projectID,
		Templates: templates,
	}, nil
}
