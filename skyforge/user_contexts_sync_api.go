package skyforge

import (
	"context"
	"time"

	"encore.dev/beta/errs"
)

type UserContextsSyncResponse struct {
	Updated   int                     `json:"updated"`
	Errors    int                     `json:"errors"`
	Reports   []userContextSyncReport `json:"reports"`
	Timestamp string                  `json:"timestamp"`
}

// SyncUserContexts syncs all user contexts from external systems (admin only).
//
//encore:api auth method=POST path=/api/admin/user-contexts/sync tag:admin
func (s *Service) SyncUserContexts(ctx context.Context) (*UserContextsSyncResponse, error) {
	userContextSyncAdminRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		userContextSyncFailures.Add(1)
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) {
		userContextSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	reports, err := syncUserContexts(ctx, s.cfg, s.userContextStore, s.db)
	if err != nil {
		userContextSyncFailures.Add(1)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync user contexts").Err()
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
		userContextSyncErrors.Add(uint64(withErrors))
	}
	return &UserContextsSyncResponse{
		Updated:   updated,
		Errors:    withErrors,
		Reports:   reports,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
