package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
)

type TemplatesParams struct {
	UserID string `query:"user_id" encore:"optional"`
	Cookie string `header:"Cookie"`
}

type TemplatesResponse struct {
	User      string            `json:"user"`
	UserID    string            `json:"userId"`
	Templates []TemplateSummary `json:"templates"`
}

// GetTemplates returns available templates for a user scope.
//
//encore:api public method=GET path=/api/templates
func (s *Service) GetTemplates(ctx context.Context, params *TemplatesParams) (*TemplatesResponse, error) {
	userID := ""
	if params != nil {
		userID = strings.TrimSpace(params.UserID)
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
			UserID:    userID,
			Templates: []TemplateSummary{},
		}, nil
	}
	if userID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user_id is required").Err()
	}

	userScopes, err := s.userScopeStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load userScopes").Err()
	}
	if w := findUserScopeByKey(userScopes, userID); w != nil {
		if userScopeAccessLevel(s.cfg, *w, claims.Username) == "none" {
			return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
		}
	} else {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user not found").Err()
	}

	_ = ctx
	return &TemplatesResponse{
		User:      claims.Username,
		UserID:    userID,
		Templates: []TemplateSummary{},
	}, nil
}
