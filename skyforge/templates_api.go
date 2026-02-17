package skyforge

import (
	"context"
	"strings"
)

type TemplatesParams struct {
	Cookie string `header:"Cookie"`
}

type TemplatesResponse struct {
	User          string            `json:"user"`
	UserContextID string            `json:"userContextId"`
	Templates     []TemplateSummary `json:"templates"`
}

// GetTemplates returns available templates for the current user context.
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
			User:          "",
			UserContextID: "",
			Templates:     []TemplateSummary{},
		}, nil
	}

	user := &AuthUser{
		Username:      strings.ToLower(strings.TrimSpace(claims.Username)),
		DisplayName:   claims.DisplayName,
		Email:         claims.Email,
		Groups:        claims.Groups,
		ActorUsername: strings.ToLower(strings.TrimSpace(claims.ActorUsername)),
		Impersonating: isImpersonating(claims),
		IsAdmin:       isAdminUser(s.cfg, adminUsernameForClaims(claims)),
	}
	userContext, err := s.resolveUserContextForUser(ctx, user, "")
	if err != nil {
		return nil, err
	}

	_ = ctx
	return &TemplatesResponse{
		User:          claims.Username,
		UserContextID: userContext.ID,
		Templates:     []TemplateSummary{},
	}, nil
}
