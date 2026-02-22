package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
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

	UserScopesTotal   int `json:"userScopesTotal,omitempty"`
	DeploymentsTotal  int `json:"deploymentsTotal,omitempty"`
	DeploymentsActive int `json:"deploymentsActive,omitempty"`
}

func tcpDialCheck(ctx context.Context, addr string, timeout time.Duration) error {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func countUserScopes(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil {
		return 0, nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_user_scopes`).Scan(&count); err != nil {
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
// This is designed for an unauthenticated landing page and must not leak user/user-scope identifiers.
//
//encore:api public method=GET path=/status/summary
func (s *Service) StatusSummary(ctx context.Context) (*StatusSummaryResponse, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	resp := &StatusSummaryResponse{Status: "unknown", Timestamp: now}

	resp.Checks = append(resp.Checks, StatusCheckResponse{
		Name:   "skyforge-api",
		Status: "up",
	})

	if v := skyforgecore.ValidateConfig(s.cfg); len(v.Errors) > 0 {
		resp.Checks = append(resp.Checks, StatusCheckResponse{
			Name:   "config",
			Status: "down",
			Detail: fmt.Sprintf("%d error(s)", len(v.Errors)),
		})
	} else if len(v.Warnings) > 0 {
		resp.Checks = append(resp.Checks, StatusCheckResponse{
			Name:   "config",
			Status: "up",
			Detail: fmt.Sprintf("%d warning(s)", len(v.Warnings)),
		})
	} else {
		resp.Checks = append(resp.Checks, StatusCheckResponse{
			Name:   "config",
			Status: "up",
		})
	}

	// Infra dependency checks (best-effort, do not leak environment details).
	{
		ctxDial, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		if err := tcpDialCheck(ctxDial, "nsq:4150", 400*time.Millisecond); err != nil {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "nsq",
				Status: "down",
				Detail: "connect failed",
			})
		} else {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "nsq",
				Status: "up",
			})
		}
	}
	{
		ctxDial, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		if err := tcpDialCheck(ctxDial, "redis:6379", 400*time.Millisecond); err != nil {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "redis",
				Status: "down",
				Detail: "connect failed",
			})
		} else {
			resp.Checks = append(resp.Checks, StatusCheckResponse{
				Name:   "redis",
				Status: "up",
			})
		}
	}

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
		workerDetail := "unknown"
		workerStatus := "down"
		if s.cfg.TaskWorkerEnabled {
			age, err := taskheartbeats.MostRecentWorkerHeartbeatAgeSeconds(ctx, s.db)
			if err == nil {
				workerDetail = fmt.Sprintf("heartbeat_age=%.0fs", age)
				// With Encore cron expected to run every ~60s, treat staleness beyond 2 minutes as degraded.
				switch {
				case age <= 0:
					workerStatus = "down"
				case age <= 120:
					workerStatus = "up"
				default:
					workerStatus = "down"
				}
			} else {
				workerDetail = "heartbeat query failed"
			}
		} else {
			workerDetail = "disabled"
			workerStatus = "up"
		}
		resp.Checks = append(resp.Checks, StatusCheckResponse{
			Name:   "task-workers",
			Status: workerStatus,
			Detail: workerDetail,
		})
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

	if total, err := countUserScopes(ctx, s.db); err == nil {
		resp.UserScopesTotal = total
	}
	if total, active, err := countDeployments(ctx, s.db); err == nil {
		resp.DeploymentsTotal = total
		resp.DeploymentsActive = active
	}

	return resp, nil
}
