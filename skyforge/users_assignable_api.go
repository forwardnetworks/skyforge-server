package skyforge

import (
	"context"
	"sort"
	"strings"

	"encore.dev/beta/errs"
)

type AssignableUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Display  string `json:"display,omitempty"`
	Email    string `json:"email,omitempty"`
}

type AssignableUsersResponse struct {
	Users []AssignableUser `json:"users"`
}

func isShareableUser(cfg Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	// Never allow sharing to admin/system users.
	if isAdminUser(cfg, username) {
		return false
	}
	if strings.EqualFold(username, "skyforge") || strings.EqualFold(username, "system") {
		return false
	}
	return true
}

// ListAssignableUsers lists users that can be shared on user scopes.
//
// Skyforge uses username-based identities, so `id` is the username.
//
//encore:api auth method=GET path=/users/assignable
func (s *Service) ListAssignableUsers(ctx context.Context) (*AssignableUsersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}

	username := strings.ToLower(strings.TrimSpace(user.Username))
	if username == "" {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}

	seed := map[string]AssignableUser{}
	if isShareableUser(s.cfg, username) {
		seed[username] = AssignableUser{ID: username, Username: username, Display: username}
	}

	if s.db == nil {
		out := []AssignableUser{}
		if u, ok := seed[username]; ok {
			out = append(out, u)
		}
		return &AssignableUsersResponse{Users: out}, nil
	}

	// Ensure current user exists for downstream flows.
	_, _ = s.db.ExecContext(ctx, `INSERT INTO sf_users (username, created_at) VALUES ($1, now()) ON CONFLICT (username) DO NOTHING`, username)

	rows, err := s.db.QueryContext(ctx, `SELECT username FROM sf_users ORDER BY username ASC LIMIT 500`)
	if err != nil {
		// Non-fatal: return current user only.
		out := []AssignableUser{seed[username]}
		return &AssignableUsersResponse{Users: out}, nil
	}
	defer rows.Close()

	ldapBindDN := strings.TrimSpace(s.cfg.LDAPLookupBindDN)
	ldapBindPassword := s.cfg.LDAPLookupBindPassword
	canLookup := strings.TrimSpace(s.cfg.LDAP.URL) != "" && strings.TrimSpace(s.cfg.LDAP.BindTemplate) != ""
	if ldapBindDN != "" && ldapBindPassword != "" && canLookup {
		// ok
	} else {
		canLookup = false
	}

	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			continue
		}
		u = strings.ToLower(strings.TrimSpace(u))
		if u == "" {
			continue
		}
		if !isShareableUser(s.cfg, u) {
			continue
		}
		entry := AssignableUser{ID: u, Username: u, Display: u}
		if canLookup {
			if prof, err := lookupLDAPUserProfile(ctx, s.cfg.LDAP, u, s.cfg.MaxGroups, ldapBindDN, ldapBindPassword); err == nil && prof != nil {
				if strings.TrimSpace(prof.DisplayName) != "" {
					entry.Display = strings.TrimSpace(prof.DisplayName)
				}
				if strings.TrimSpace(prof.Email) != "" {
					entry.Email = strings.TrimSpace(prof.Email)
				}
			}
		}
		seed[u] = entry
	}

	users := make([]AssignableUser, 0, len(seed))
	for _, u := range seed {
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Username < users[j].Username
	})

	return &AssignableUsersResponse{Users: users}, nil
}

type UserSearchResponse struct {
	Users []AssignableUser `json:"users"`
}

type UserSearchRequest struct {
	Query string `query:"q" encore:"optional"`
}

// SearchUsers searches LDAP for users matching q.
//
//encore:api auth method=GET path=/users/search
func (s *Service) SearchUsers(ctx context.Context, req *UserSearchRequest) (*UserSearchResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	_ = user

	query := ""
	if req != nil {
		query = strings.ToLower(strings.TrimSpace(req.Query))
	}
	if query == "" {
		return &UserSearchResponse{Users: []AssignableUser{}}, nil
	}
	if len(query) < 2 {
		return &UserSearchResponse{Users: []AssignableUser{}}, nil
	}

	ldapBindDN := strings.TrimSpace(s.cfg.LDAPLookupBindDN)
	ldapBindPassword := s.cfg.LDAPLookupBindPassword
	if strings.TrimSpace(s.cfg.LDAP.URL) == "" || strings.TrimSpace(s.cfg.LDAP.BindTemplate) == "" {
		return &UserSearchResponse{Users: []AssignableUser{}}, nil
	}

	results, err := searchLDAPUsers(ctx, s.cfg.LDAP, query, ldapBindDN, ldapBindPassword, 30)
	if err != nil {
		// Non-fatal: empty results.
		return &UserSearchResponse{Users: []AssignableUser{}}, nil
	}
	filtered := make([]AssignableUser, 0, len(results))
	for _, u := range results {
		if !isShareableUser(s.cfg, u.Username) {
			continue
		}
		filtered = append(filtered, u)
	}
	return &UserSearchResponse{Users: filtered}, nil
}
