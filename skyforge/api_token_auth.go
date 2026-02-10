package skyforge

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

func (s *Service) authUserFromAPIToken(ctx context.Context, token string) (*AuthUser, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	username, _, err := lookupUserByAPIToken(ctx, s.db, token)
	if err != nil {
		return nil, err
	}
	if username == "" {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("invalid token").Err()
	}

	// Pull basic profile info for nicer UI logging / debugging; groups are session-derived.
	var displayName sql.NullString
	var email sql.NullString
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = s.db.QueryRowContext(ctx2, `SELECT display_name, email FROM sf_users WHERE username=$1`, username).Scan(&displayName, &email)

	u := &AuthUser{
		Username:      strings.ToLower(strings.TrimSpace(username)),
		DisplayName:   strings.TrimSpace(displayName.String),
		Email:         strings.TrimSpace(email.String),
		Groups:        []string{},
		ActorUsername: "",
		Impersonating: false,
		IsAdmin:       isAdminUser(s.cfg, username),
		SelectedRole:  "",
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = u.Username
	}
	return u, nil
}
