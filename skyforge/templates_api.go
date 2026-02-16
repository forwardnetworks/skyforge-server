package skyforge

import (
	"context"
)

type TemplatesParams struct {
	Cookie string `header:"Cookie"`
}

type TemplatesResponse struct {
	User      string            `json:"user"`
	Templates []TemplateSummary `json:"templates"`
}

// GetTemplates returns available templates for the current user.
//
//encore:api public method=GET path=/api/templates
func (s *Service) GetTemplates(ctx context.Context, params *TemplatesParams) (*TemplatesResponse, error) {
	claims := claimsFromCookie(s.sessionManager, func() string {
		if params == nil {
			return ""
		}
		return params.Cookie
	}())
	if claims == nil {
		return &TemplatesResponse{
			User:      "",
			Templates: []TemplateSummary{},
		}, nil
	}

	_ = ctx
	return &TemplatesResponse{
		User:      claims.Username,
		Templates: []TemplateSummary{},
	}, nil
}
