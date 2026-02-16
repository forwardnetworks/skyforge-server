package taskreconcile

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/tasknotify"
)

func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, ownerID, deploymentID, status string, finishedAt time.Time) error {
	if db == nil {
		return sql.ErrConnDone
	}
	ownerID = strings.TrimSpace(ownerID)
	deploymentID = strings.TrimSpace(deploymentID)
	status = strings.TrimSpace(status)
	if ownerID == "" || deploymentID == "" || status == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  last_finished_at=$2,
  updated_at=now()
WHERE owner_id=$3 AND id=$4`, status, finishedAt.UTC(), ownerID, deploymentID)
	if err == nil {
		_ = tasknotify.NotifyDeploymentEvent(ctx, db, ownerID, deploymentID)
		_ = tasknotify.NotifyDashboardUpdate(ctx, db)
	}
	return err
}
