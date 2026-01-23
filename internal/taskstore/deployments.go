package taskstore

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, workspaceID, deploymentID string, status string, finishedAt *time.Time) error {
	if db == nil {
		return errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	if workspaceID == "" || deploymentID == "" {
		return nil
	}
	var finished sql.NullTime
	if finishedAt != nil && !finishedAt.IsZero() {
		finished = sql.NullTime{Time: *finishedAt, Valid: true}
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_deployments SET status=$1, last_run_at=$2 WHERE id=$3 AND workspace_id=$4`,
		status, finished, deploymentID, workspaceID)
	return err
}

// Note: queue helpers live in queries.go.
