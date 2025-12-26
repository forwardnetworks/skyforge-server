package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
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

	ProjectsTotal int `json:"projectsTotal,omitempty"`
}

func countProjects(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil {
		return 0, nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_projects`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// StatusSummary returns a public, safe platform status summary.
//
// This is designed for an unauthenticated landing page and must not leak user/project identifiers.
//
//encore:api public method=GET path=/status/summary
func (s *Service) StatusSummary(ctx context.Context) (*StatusSummaryResponse, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	resp := &StatusSummaryResponse{Status: "unknown", Timestamp: now}

	if s.cfg.PlatformDataDir != "" {
		path := filepath.Join(s.cfg.PlatformDataDir, "platform-health.json")
		if data, err := os.ReadFile(path); err == nil {
			var checks []StatusCheckResponse
			if err := json.Unmarshal(data, &checks); err == nil {
				resp.Checks = checks
				for _, c := range checks {
					if strings.EqualFold(strings.TrimSpace(c.Status), "up") {
						resp.Up++
					} else {
						resp.Down++
					}
				}
				switch {
				case len(checks) == 0:
					resp.Status = "unknown"
				case resp.Down == 0:
					resp.Status = "ok"
				default:
					resp.Status = "degraded"
				}
			}
		}
	}

	if total, err := countProjects(ctx, s.db); err == nil {
		resp.ProjectsTotal = total
	}

	return resp, nil
}
