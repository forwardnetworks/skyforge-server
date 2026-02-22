package taskreconcile

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/tasknotify"
)

func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, userScopeID, deploymentID, status string, finishedAt time.Time) error {
	if db == nil {
		return sql.ErrConnDone
	}
	userScopeID = strings.TrimSpace(userScopeID)
	deploymentID = strings.TrimSpace(deploymentID)
	status = strings.TrimSpace(status)
	if userScopeID == "" || deploymentID == "" || status == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  last_finished_at=$2,
  updated_at=now()
WHERE username=$3 AND id=$4`, status, finishedAt.UTC(), userScopeID, deploymentID)
	if err == nil {
		_ = tasknotify.NotifyDeploymentEvent(ctx, db, userScopeID, deploymentID)
		_ = tasknotify.NotifyDashboardUpdate(ctx, db)
	}
	return err
}
