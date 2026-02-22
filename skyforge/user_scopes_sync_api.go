package skyforge

import (
	"context"
	"time"

	"encore.dev/beta/errs"
)

type UserScopesSyncResponse struct {
	Updated   int                   `json:"updated"`
	Errors    int                   `json:"errors"`
	Reports   []userScopeSyncReport `json:"reports"`
	Timestamp string                `json:"timestamp"`
}

// SyncUserScopes syncs all user scopes from external systems (admin only).
//
//encore:api auth method=POST path=/api/admin/users/sync tag:admin
func (s *Service) SyncUserScopes(ctx context.Context) (*UserScopesSyncResponse, error) {
	userScopeSyncAdminRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		userScopeSyncFailures.Add(1)
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) {
		userScopeSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	reports, err := syncUserScopes(ctx, s.cfg, s.userScopeStore, s.db)
	if err != nil {
		userScopeSyncFailures.Add(1)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync user scopes").Err()
	}
	updated := 0
	withErrors := 0
	for _, report := range reports {
		if report.Updated {
			updated++
		}
		if len(report.Errors) > 0 {
			withErrors++
		}
	}
	if withErrors > 0 {
		userScopeSyncErrors.Add(uint64(withErrors))
	}
	return &UserScopesSyncResponse{
		Updated:   updated,
		Errors:    withErrors,
		Reports:   reports,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
