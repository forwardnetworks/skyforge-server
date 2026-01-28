package taskstore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/tasknotify"
)

func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, workspaceID, deploymentID string, status string, finishedAt *time.Time) error {
	if db == nil {
		return errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	status = strings.TrimSpace(status)
	if workspaceID == "" || deploymentID == "" {
		return nil
	}
	if status == "" {
		return nil
	}
	var finished sql.NullTime
	if finishedAt != nil && !finishedAt.IsZero() {
		finished = sql.NullTime{Time: finishedAt.UTC(), Valid: true}
	}
	// Keep this in sync with sf_deployments schema. The UI reads last_status/last_finished_at.
	_, err := db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  last_finished_at=$2,
  updated_at=now()
WHERE id=$3 AND workspace_id=$4`,
		status, finished, deploymentID, workspaceID)
	if err == nil {
		_ = tasknotify.NotifyDeploymentEvent(ctx, db, workspaceID, deploymentID)
		_ = tasknotify.NotifyDashboardUpdate(ctx, db)
	}
	return err
}

// Note: queue helpers live in queries.go.
