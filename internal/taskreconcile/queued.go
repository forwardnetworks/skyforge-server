package taskreconcile

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type QueuedTask struct {
	TaskID    int
	Key       string
	Priority  int
	CreatedAt time.Time
}

func ListQueuedTasks(ctx context.Context, db *sql.DB, limit int) ([]QueuedTask, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 {
		limit = 200
	}

	rows, err := db.QueryContext(ctx, `SELECT id, owner_id, deployment_id, priority, created_at
FROM sf_tasks
WHERE status='queued'
ORDER BY priority DESC, id ASC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type row struct {
		id           int
		ownerID      string
		deploymentID sql.NullString
		priority     int
		createdAt    time.Time
	}
	items := make([]QueuedTask, 0, 64)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ownerID, &r.deploymentID, &r.priority, &r.createdAt); err != nil {
			return nil, err
		}
		if r.id <= 0 || strings.TrimSpace(r.ownerID) == "" {
			continue
		}
		key := strings.TrimSpace(r.ownerID)
		if r.deploymentID.Valid && strings.TrimSpace(r.deploymentID.String) != "" {
			key = fmt.Sprintf("%s:%s", strings.TrimSpace(r.ownerID), strings.TrimSpace(r.deploymentID.String))
		}
		items = append(items, QueuedTask{
			TaskID:    r.id,
			Key:       key,
			Priority:  r.priority,
			CreatedAt: r.createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// ListStuckQueuedTasksByKey returns at most one queued task per (owner_id, deployment_id),
// selecting the oldest (highest priority, then lowest id) for each key.
//
// This is used as a DB-backed fallback for environments where Pub/Sub delivery might be delayed
// or unavailable. The minAge guard helps avoid racing normal Pub/Sub delivery.
func ListStuckQueuedTasksByKey(ctx context.Context, db *sql.DB, limit int, minAge time.Duration) ([]QueuedTask, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 {
		limit = 50
	}
	if minAge < 0 {
		minAge = 0
	}

	ageStr := fmt.Sprintf("%fs", minAge.Seconds())
	// NOTE: deployment_id is a UUID column. We cast to text before COALESCE to avoid invalid
	// UUID casts when comparing NULL deployments (owner-bound tasks).
	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT ON (owner_id, COALESCE(deployment_id::text, ''))
  id, owner_id, deployment_id, priority, created_at
FROM sf_tasks
WHERE status='queued'
  AND created_at <= now() - $2::interval
ORDER BY owner_id, COALESCE(deployment_id::text, ''), priority DESC, id ASC
LIMIT $1`, limit, ageStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type row struct {
		id           int
		ownerID      string
		deploymentID sql.NullString
		priority     int
		createdAt    time.Time
	}
	items := make([]QueuedTask, 0, 32)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ownerID, &r.deploymentID, &r.priority, &r.createdAt); err != nil {
			return nil, err
		}
		if r.id <= 0 || strings.TrimSpace(r.ownerID) == "" {
			continue
		}
		key := strings.TrimSpace(r.ownerID)
		if r.deploymentID.Valid && strings.TrimSpace(r.deploymentID.String) != "" {
			key = fmt.Sprintf("%s:%s", strings.TrimSpace(r.ownerID), strings.TrimSpace(r.deploymentID.String))
		}
		items = append(items, QueuedTask{
			TaskID:    r.id,
			Key:       key,
			Priority:  r.priority,
			CreatedAt: r.createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
