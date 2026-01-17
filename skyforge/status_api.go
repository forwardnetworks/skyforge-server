package skyforge

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/taskheartbeats"
)

type StatusCheckResponse struct {
	Name   string `json:"name"`
	Icon   string `json:"icon,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type StatusSummaryResponse struct {
	Status    string                `json:"status"` // ok|degraded|unknown
	Timestamp string                `json:"timestamp"`
	Up        int                   `json:"up"`
	Down      int                   `json:"down"`
	Checks    []StatusCheckResponse `json:"checks,omitempty"`

	WorkspacesTotal int `json:"workspacesTotal,omitempty"`
}

func countWorkspaces(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil {
		return 0, nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_workspaces`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// StatusSummary returns a public, safe platform status summary.
//
// This is designed for an unauthenticated landing page and must not leak user/workspace identifiers.
//
//encore:api public method=GET path=/status/summary
func (s *Service) StatusSummary(ctx context.Context) (*StatusSummaryResponse, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	resp := &StatusSummaryResponse{Status: "unknown", Timestamp: now}

	resp.Checks = append(resp.Checks, StatusCheckResponse{
		Name:   "skyforge-api",
		Status: "up",
	})
	if s.db == nil {
		resp.Checks = append(resp.Checks, StatusCheckResponse{
			Name:   "postgres",
			Status: "down",
			Detail: "db not configured",
		})
	} else {
		ctxPing, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := s.db.PingContext(ctxPing); err != nil {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "postgres",
				Status: "down",
				Detail: "ping failed",
			})
		} else {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "postgres",
				Status: "up",
			})
		}
		if n, err := taskheartbeats.CountWorkerHeartbeats(ctx, s.db, 90*time.Second); err == nil && n > 0 {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "task-workers",
				Status: "up",
				Detail: "active",
			})
		} else {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "task-workers",
				Status: "down",
				Detail: "no recent heartbeats",
			})
		}
	}

	for _, c := range resp.Checks {
		if strings.EqualFold(strings.TrimSpace(c.Status), "up") {
			resp.Up++
		} else {
			resp.Down++
		}
	}
	switch {
	case len(resp.Checks) == 0:
		resp.Status = "unknown"
	case resp.Down == 0:
		resp.Status = "ok"
	default:
		resp.Status = "degraded"
	}

	if total, err := countWorkspaces(ctx, s.db); err == nil {
		resp.WorkspacesTotal = total
	}

	return resp, nil
}
