package skyforge

import (
	"context"
	"net/http"
	"strings"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

// AuthParams defines the parameters for authentication.
type AuthParams struct {
	Cookie      string `header:"Cookie"`
	CurrentRole string `header:"X-Current-Role"`
}

// AuthUser represents the authenticated user data stored in auth.Data().
type AuthUser struct {
	Username      string   `json:"username"`
	DisplayName   string   `json:"displayName"`
	Email         string   `json:"email,omitempty"`
	Groups        []string `json:"groups"`
	ActorUsername string   `json:"actorUsername,omitempty"`
	Impersonating bool     `json:"impersonating"`
	IsAdmin       bool     `json:"isAdmin"`
	SelectedRole  string   `json:"selectedRole,omitempty"`
}

// AuthHandler authenticates incoming requests using the Skyforge session cookie.
//
//encore:authhandler
func (s *Service) AuthHandler(ctx context.Context, p *AuthParams) (auth.UID, *AuthUser, error) {
	cookieHeader := strings.TrimSpace(p.Cookie)
	if cookieHeader == "" {
		return "", nil, &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "missing session cookie",
		}
	}

	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		rlog.Debug("auth handler rejected session", "error", err)
		return "", nil, &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "invalid session",
		}
	}

	user := &AuthUser{
		Username:      claims.Username,
		DisplayName:   claims.DisplayName,
		Email:         claims.Email,
		Groups:        claims.Groups,
		ActorUsername: claims.ActorUsername,
		Impersonating: isImpersonating(claims),
		IsAdmin:       isAdminUser(s.cfg, adminUsernameForClaims(claims)),
		SelectedRole:  "",
	}

	selectedRole := strings.ToUpper(strings.TrimSpace(p.CurrentRole))
	if selectedRole == "" {
		if user.IsAdmin {
			selectedRole = "ADMIN"
		} else {
			selectedRole = "USER"
		}
	}
	if selectedRole == "ADMIN" && !user.IsAdmin {
		selectedRole = "USER"
	}
	user.SelectedRole = selectedRole

	return auth.UID(claims.Username), user, nil
}
