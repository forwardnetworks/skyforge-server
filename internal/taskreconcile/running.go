package taskreconcile

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type RunningTask struct {
	TaskID       int
	UserScopeID  string
	DeploymentID string
	StartedAt    time.Time
}

type RunningReconcileOptions struct {
	Limit          int
	HardMaxRuntime time.Duration
	MaxIdle        time.Duration
}

func FindStuckRunningTasks(ctx context.Context, db *sql.DB, opts RunningReconcileOptions) ([]RunningTask, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	// Conservative defaults to avoid false positives.
	hardMaxRuntime := opts.HardMaxRuntime
	if hardMaxRuntime <= 0 {
		hardMaxRuntime = 12 * time.Hour
	}
	maxIdle := opts.MaxIdle
	if maxIdle <= 0 {
		maxIdle = 2 * time.Hour
	}

	cutoffHard := time.Now().Add(-hardMaxRuntime).UTC()
	cutoffIdle := time.Now().Add(-maxIdle).UTC()

	rows, err := db.QueryContext(ctx, `SELECT id, username, deployment_id, started_at
FROM sf_tasks
WHERE status='running'
  AND started_at IS NOT NULL
  AND (
    started_at < $1 OR
    NOT EXISTS (
      SELECT 1
      FROM sf_task_logs l
      WHERE l.task_id = sf_tasks.id
        AND l.created_at >= $2
    )
  )
ORDER BY id ASC
LIMIT $3`, cutoffHard, cutoffIdle, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type row struct {
		id           int
		userScopeID  string
		deploymentID sql.NullString
		startedAt    time.Time
	}
	out := make([]RunningTask, 0, 16)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.userScopeID, &r.deploymentID, &r.startedAt); err != nil {
			return nil, err
		}
		if r.id <= 0 || strings.TrimSpace(r.userScopeID) == "" {
			continue
		}
		dep := ""
		if r.deploymentID.Valid {
			dep = strings.TrimSpace(r.deploymentID.String)
		}
		out = append(out, RunningTask{
			TaskID:       r.id,
			UserScopeID:  strings.TrimSpace(r.userScopeID),
			DeploymentID: dep,
			StartedAt:    r.startedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
