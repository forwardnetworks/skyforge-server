package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"encore.app/internal/taskqueue"
	"encore.dev/rlog"
)

func (s *Service) queueTask(task *TaskRecord) {
	if s == nil || task == nil {
		return
	}
	s.enqueueTask(context.Background(), task)
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
