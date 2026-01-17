package taskreconcile

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type QueuedTask struct {
	TaskID   int
	Key      string
	Priority int
}

func ListQueuedTasks(ctx context.Context, db *sql.DB, limit int) ([]QueuedTask, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 {
		limit = 200
	}

	rows, err := db.QueryContext(ctx, `SELECT id, workspace_id, deployment_id, priority
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
		workspaceID  string
		deploymentID sql.NullString
		priority     int
	}
	items := make([]QueuedTask, 0, 64)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.workspaceID, &r.deploymentID, &r.priority); err != nil {
			return nil, err
		}
		if r.id <= 0 || strings.TrimSpace(r.workspaceID) == "" {
			continue
		}
		key := strings.TrimSpace(r.workspaceID)
		if r.deploymentID.Valid && strings.TrimSpace(r.deploymentID.String) != "" {
			key = fmt.Sprintf("%s:%s", strings.TrimSpace(r.workspaceID), strings.TrimSpace(r.deploymentID.String))
		}
		items = append(items, QueuedTask{
			TaskID:   r.id,
			Key:      key,
			Priority: r.priority,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
