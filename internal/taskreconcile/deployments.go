package taskreconcile

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/tasknotify"
)

func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, workspaceID, deploymentID, status string, finishedAt time.Time) error {
	if db == nil {
		return sql.ErrConnDone
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	status = strings.TrimSpace(status)
	if workspaceID == "" || deploymentID == "" || status == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  last_finished_at=$2,
  updated_at=now()
WHERE user_id=$3 AND id=$4`, status, finishedAt.UTC(), workspaceID, deploymentID)
	if err == nil {
		_ = tasknotify.NotifyDeploymentEvent(ctx, db, workspaceID, deploymentID)
		_ = tasknotify.NotifyDashboardUpdate(ctx, db)
	}
	return err
}
