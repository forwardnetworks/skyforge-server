package skyforge

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type InternalNotifyTaskStatusParams struct {
	TaskID int    `json:"taskId"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// InternalNotifyTaskStatus performs best-effort side effects for a task status transition:
// - create user notifications
// - update deployment status fields
// - trigger pg_notify updates so SSE streams refresh quickly
//
// Task status updates in sf_tasks are handled by the worker.
//
//encore:api private method=POST path=/internal/tasks/notify
func (s *Service) InternalNotifyTaskStatus(ctx context.Context, params *InternalNotifyTaskStatusParams) error {
	if s == nil || s.db == nil {
		return nil
	}
	if params == nil || params.TaskID <= 0 {
		return nil
	}
	task, err := getTask(ctx, s.db, params.TaskID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("task not found")
	}
	status := strings.TrimSpace(params.Status)
	errMsg := strings.TrimSpace(params.Error)

	_ = s.notifyTaskEvent(ctx, task, status, errMsg)

	if task.DeploymentID.Valid {
		t := time.Now().UTC()
		_ = s.updateDeploymentStatus(ctx, task.WorkspaceID, strings.TrimSpace(task.DeploymentID.String), status, &t)
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	// Always nudge task streams.
	_ = notifyTaskUpdatePG(ctx, s.db, task.ID)
	return nil
}
