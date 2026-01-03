package skyforge

import (
	"context"
	"time"

	"encore.dev/beta/errs"
)

type WorkspacesSyncResponse struct {
	Updated   int                   `json:"updated"`
	Errors    int                   `json:"errors"`
	Reports   []workspaceSyncReport `json:"reports"`
	Timestamp string                `json:"timestamp"`
}

// SyncWorkspaces syncs all workspaces from external systems (admin only).
//
//encore:api auth method=POST path=/api/admin/workspaces/sync tag:admin
func (s *Service) SyncWorkspaces(ctx context.Context) (*WorkspacesSyncResponse, error) {
	workspaceSyncAdminRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		workspaceSyncFailures.Add(1)
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) {
		workspaceSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	reports, err := syncWorkspaces(ctx, s.cfg, s.workspaceStore, s.db)
	if err != nil {
		workspaceSyncFailures.Add(1)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync workspaces").Err()
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
		workspaceSyncErrors.Add(uint64(withErrors))
	}
	return &WorkspacesSyncResponse{
		Updated:   updated,
		Errors:    withErrors,
		Reports:   reports,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
