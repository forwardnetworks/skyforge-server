package skyforge

import (
	"context"
	"time"

	"encore.dev/beta/errs"
)

type ProjectsSyncResponse struct {
	Updated   int                 `json:"updated"`
	Errors    int                 `json:"errors"`
	Reports   []projectSyncReport `json:"reports"`
	Timestamp string              `json:"timestamp"`
}

// SyncProjects syncs all projects from external systems (admin only).
//
//encore:api auth method=POST path=/api/admin/projects/sync tag:admin
func (s *Service) SyncProjects(ctx context.Context) (*ProjectsSyncResponse, error) {
	projectSyncAdminRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		projectSyncFailures.Add(1)
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) {
		projectSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	reports, err := syncProjects(ctx, s.cfg, s.projectStore, s.db)
	if err != nil {
		projectSyncFailures.Add(1)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to sync projects").Err()
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
		projectSyncProjectErrors.Add(uint64(withErrors))
	}
	return &ProjectsSyncResponse{
		Updated:   updated,
		Errors:    withErrors,
		Reports:   reports,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
