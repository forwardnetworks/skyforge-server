package skyforge

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"encore.dev/beta/errs"
)

func requireUserScopeOwner(ctx context.Context, s *Service, userScopeID string) (*userContext, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, userScopeID)
	if err != nil {
		return nil, err
	}
	access := userScopeAccessLevelForClaims(s.cfg, pc.userScope, pc.claims)
	if access != "owner" && access != "admin" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return pc, nil
}

func validateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return "", fmt.Errorf("invalid url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("url must be http(s)")
	}
	return strings.TrimRight(raw, "/"), nil
}
