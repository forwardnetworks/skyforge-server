package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"encore.app/internal/taskqueue"
	"encore.dev/rlog"
)

// ReconcileQueuedTasks republishes queue events for tasks stuck in the "queued" state.
//
//encore:api private method=POST path=/internal/tasks/reconcile
func ReconcileQueuedTasks(ctx context.Context) error {
	if defaultService == nil || defaultService.db == nil {
		return nil
	}
	return reconcileQueuedTasks(ctx, defaultService)
}

func reconcileQueuedTasks(ctx context.Context, svc *Service) error {
	if svc == nil || svc.db == nil {
		return nil
	}
	db := svc.db
	rows, err := db.QueryContext(ctx, `SELECT id, workspace_id, deployment_id, priority
FROM sf_tasks
WHERE status='queued'
ORDER BY priority DESC, id ASC
LIMIT 200`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type queued struct {
		id           int
		workspaceID  string
		deploymentID sql.NullString
		priority     int
	}
	items := make([]queued, 0, 128)
	for rows.Next() {
		var q queued
		if err := rows.Scan(&q.id, &q.workspaceID, &q.deploymentID, &q.priority); err != nil {
			return err
		}
		if q.id > 0 && strings.TrimSpace(q.workspaceID) != "" {
			items = append(items, q)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, q := range items {
		key := strings.TrimSpace(q.workspaceID)
		if q.deploymentID.Valid && strings.TrimSpace(q.deploymentID.String) != "" {
			key = fmt.Sprintf("%s:%s", strings.TrimSpace(q.workspaceID), strings.TrimSpace(q.deploymentID.String))
		}
		if q.priority < taskPriorityInteractive {
			if _, err := taskQueueBackgroundTopic.Publish(ctx, &taskqueue.TaskEnqueuedEvent{TaskID: q.id, Key: key}); err != nil {
				rlog.Error("task reconcile publish failed", "task_id", q.id, "err", err)
			}
			continue
		}
		if _, err := taskQueueInteractiveTopic.Publish(ctx, &taskqueue.TaskEnqueuedEvent{TaskID: q.id, Key: key}); err != nil {
			rlog.Error("task reconcile publish failed", "task_id", q.id, "err", err)
		}
	}

	return nil
}

func (s *Service) enqueueTask(ctx context.Context, task *TaskRecord) {
	if s == nil || task == nil || task.ID <= 0 {
		return
	}
	deploymentID := ""
	if task.DeploymentID.Valid {
		deploymentID = strings.TrimSpace(task.DeploymentID.String)
	}
	s.enqueueTaskID(ctx, task.ID, task.WorkspaceID, deploymentID, task.Priority)
}

func (s *Service) enqueueTaskID(ctx context.Context, taskID int, workspaceID string, deploymentID string, priority int) {
	if s == nil || taskID <= 0 {
		return
	}
	if priority == 0 && s.db != nil {
		var p sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT priority FROM sf_tasks WHERE id=$1`, taskID).Scan(&p); err == nil && p.Valid {
			priority = int(p.Int64)
		}
	}
	key := strings.TrimSpace(workspaceID)
	if strings.TrimSpace(deploymentID) != "" {
		key = fmt.Sprintf("%s:%s", strings.TrimSpace(workspaceID), strings.TrimSpace(deploymentID))
	}
	if priority < taskPriorityInteractive {
		if _, err := taskQueueBackgroundTopic.Publish(ctx, &taskqueue.TaskEnqueuedEvent{TaskID: taskID, Key: key}); err != nil {
			rlog.Error("task enqueue publish failed", "task_id", taskID, "err", err)
		}
		return
	}
	if _, err := taskQueueInteractiveTopic.Publish(ctx, &taskqueue.TaskEnqueuedEvent{TaskID: taskID, Key: key}); err != nil {
		rlog.Error("task enqueue publish failed", "task_id", taskID, "err", err)
	}
}
