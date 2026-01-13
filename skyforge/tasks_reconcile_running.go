package skyforge

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/cron"
)

// Reconcile running tasks periodically so they aren't stranded if the server
// restarts mid-run or a runner crashes without reporting completion.
var _ = cron.NewJob("skyforge-reconcile-running-tasks", cron.JobConfig{
	Title:    "Mark stuck running Skyforge tasks as failed",
	Every:    10 * cron.Minute,
	Endpoint: ReconcileRunningTasks,
})

// ReconcileRunningTasks finds long-running tasks that appear stuck and marks them failed.
//
//encore:api private method=POST path=/internal/tasks/reconcile-running
func ReconcileRunningTasks(ctx context.Context) error {
	if defaultService == nil || defaultService.db == nil {
		return nil
	}
	return reconcileRunningTasks(ctx, defaultService)
}

func reconcileRunningTasks(ctx context.Context, svc *Service) error {
	if svc == nil || svc.db == nil {
		return nil
	}
	db := svc.db

	type running struct {
		id           int
		workspaceID  string
		deploymentID sql.NullString
		startedAt    time.Time
	}

	// Conservative thresholds to avoid false positives.
	const hardMaxRuntime = 12 * time.Hour
	const maxIdle = 2 * time.Hour

	cutoffHard := time.Now().Add(-hardMaxRuntime).UTC()
	cutoffIdle := time.Now().Add(-maxIdle).UTC()

	rows, err := db.QueryContext(ctx, `SELECT id, workspace_id, deployment_id, started_at
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
LIMIT 50`, cutoffHard, cutoffIdle)
	if err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to query running tasks").Err()
	}
	defer rows.Close()

	items := make([]running, 0, 32)
	for rows.Next() {
		var r running
		if err := rows.Scan(&r.id, &r.workspaceID, &r.deploymentID, &r.startedAt); err != nil {
			return errs.B().Code(errs.Unavailable).Msg("failed to decode running task").Err()
		}
		if r.id > 0 && strings.TrimSpace(r.workspaceID) != "" {
			items = append(items, r)
		}
	}
	if err := rows.Err(); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to read running tasks").Err()
	}

	for _, r := range items {
		// Reload to ensure it is still running (avoid racing a legitimate completion).
		rec, err := getTask(ctx, db, r.id)
		if err != nil || rec == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rec.Status), "running") {
			continue
		}
		if strings.TrimSpace(r.workspaceID) == "" {
			continue
		}

		errMsg := "task appears stuck (no recent activity); marked failed by reconciler"
		log.Printf("reconcile running task: id=%d workspace=%s deployment=%s", r.id, r.workspaceID, r.deploymentID.String)

		if err := finishTask(ctx, db, r.id, "failed", errMsg); err != nil {
			log.Printf("reconcile running task finish failed: id=%d err=%v", r.id, err)
			continue
		}
		// Best-effort notification/deployment status update.
		if err := svc.notifyTaskEvent(ctx, rec, "failed", errMsg); err != nil {
			log.Printf("reconcile running task notify failed: id=%d err=%v", r.id, err)
		}
		if r.deploymentID.Valid && strings.TrimSpace(r.deploymentID.String) != "" {
			finishedAt := time.Now().UTC()
			if err := svc.updateDeploymentStatus(ctx, r.workspaceID, r.deploymentID.String, "failed", &finishedAt); err != nil {
				log.Printf("reconcile running task deployment status failed: id=%d err=%v", r.id, err)
			}
		}
	}

	return nil
}
