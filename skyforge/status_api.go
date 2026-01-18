package skyforge

import (
	"context"
	"database/sql"
	"fmt"
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

	WorkspacesTotal   int `json:"workspacesTotal,omitempty"`
	DeploymentsTotal  int `json:"deploymentsTotal,omitempty"`
	DeploymentsActive int `json:"deploymentsActive,omitempty"`
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

func countDeployments(ctx context.Context, db *sql.DB) (total int, active int, err error) {
	if db == nil {
		return 0, 0, nil
	}
	// Active = 'running', 'active', 'healthy', 'succeeded', 'success', 'ready'
	// (Note: 'created', 'stopped', 'failed', 'error', 'canceled' are not active)
	err = db.QueryRowContext(ctx, `
SELECT
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE lower(last_status) IN ('running', 'active', 'healthy', 'succeeded', 'success', 'ready')) AS active
FROM sf_deployments
`).Scan(&total, &active)
	if err != nil {
		return 0, 0, err
	}
	return total, active, nil
}

func taskQueueSummary(ctx context.Context, db *sql.DB) (queued int, running int, oldestQueuedAgeSeconds int, err error) {
	if db == nil {
		return 0, 0, 0, nil
	}
	// Oldest queued age is best-effort; when no queued tasks exist, it should be 0.
	var oldest sql.NullFloat64
	row := db.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM sf_tasks WHERE status='queued') AS queued,
  (SELECT COUNT(*) FROM sf_tasks WHERE status='running') AS running,
  (SELECT EXTRACT(EPOCH FROM (now() - MIN(created_at))) FROM sf_tasks WHERE status='queued') AS oldest
`)
	if err := row.Scan(&queued, &running, &oldest); err != nil {
		return 0, 0, 0, err
	}
	if oldest.Valid && oldest.Float64 > 0 {
		oldestQueuedAgeSeconds = int(oldest.Float64)
	}
	return queued, running, oldestQueuedAgeSeconds, nil
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
		ctxQ, cancelQ := context.WithTimeout(ctx, 2*time.Second)
		defer cancelQ()
		if queued, running, oldestAge, err := taskQueueSummary(ctxQ, s.db); err == nil {
			detail := fmt.Sprintf("queued=%d running=%d oldest=%ds", queued, running, oldestAge)
			status := "up"
			// Consider any queued backlog older than ~2 minutes a degraded signal.
			if queued > 0 && oldestAge >= 120 {
				status = "down"
			}
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "task-queue",
				Status: status,
				Detail: detail,
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
	if total, active, err := countDeployments(ctx, s.db); err == nil {
		resp.DeploymentsTotal = total
		resp.DeploymentsActive = active
	}

	return resp, nil
}
