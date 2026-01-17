package taskexec

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/tasklocks"
	"encore.app/internal/taskstore"
)

type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type Deps struct {
	Dispatch func(ctx context.Context, task *taskstore.TaskRecord, log Logger) error

	Notify func(ctx context.Context, task *taskstore.TaskRecord, status string, errMsg string) error

	UpdateDeploymentStatus func(ctx context.Context, workspaceID string, deploymentID string, status string, finishedAt time.Time) error

	EnqueueNextDeploymentTask func(ctx context.Context, nextTaskID int, workspaceID string, deploymentID string)

	OnStarted  func(task *taskstore.TaskRecord, startedAt time.Time)
	OnFinished func(task *taskstore.TaskRecord, status string, startedAt time.Time)
}

func ProcessQueuedTask(ctx context.Context, db *sql.DB, taskID int, deps Deps, log Logger) error {
	if db == nil || taskID <= 0 {
		return nil
	}
	if deps.Dispatch == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}

	task, err := taskstore.GetTask(ctx, db, taskID)
	if err != nil || task == nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(task.Status), "queued") {
		return nil
	}

	unlock, err := tasklocks.AcquireOrderedTaskLock(ctx, db, task)
	if err != nil {
		return err
	}
	defer unlock()

	// If the task was canceled while waiting in the queue, exit early without running it.
	if rec, err := taskstore.GetTask(ctx, db, task.ID); err == nil && rec != nil && strings.EqualFold(strings.TrimSpace(rec.Status), "canceled") {
		if deps.Notify != nil {
			_ = deps.Notify(ctx, task, "canceled", "")
		}
		if task.DeploymentID.Valid && deps.UpdateDeploymentStatus != nil {
			_ = deps.UpdateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, "canceled", time.Now())
		}
		return nil
	}

	ok, err := taskstore.MarkTaskStarted(ctx, db, task.ID)
	if err != nil || !ok {
		// Another worker started it (or it is no longer queued).
		return err
	}

	startedAt := time.Now().UTC()
	if deps.OnStarted != nil {
		deps.OnStarted(task, startedAt)
	}
	if deps.Notify != nil {
		_ = deps.Notify(ctx, task, "running", "")
	}

	runErr := deps.Dispatch(ctx, task, log)
	status := "success"
	errMsg := ""
	if runErr != nil {
		status = "failed"
		errMsg = runErr.Error()
		log.Errorf("ERROR: %s", errMsg)
	}
	if rec, recErr := taskstore.GetTask(ctx, db, task.ID); recErr == nil && rec != nil && strings.EqualFold(strings.TrimSpace(rec.Status), "canceled") {
		status = "canceled"
		errMsg = ""
	}

	if status != "canceled" {
		_ = taskstore.FinishTask(ctx, db, task.ID, status, errMsg)
	}

	if deps.OnFinished != nil {
		deps.OnFinished(task, status, startedAt)
	}

	if deps.Notify != nil {
		_ = deps.Notify(ctx, task, status, errMsg)
	}
	if task.DeploymentID.Valid && deps.UpdateDeploymentStatus != nil {
		_ = deps.UpdateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, status, time.Now())
	}

	// Kick the next queued task for this deployment. This reduces reliance on periodic
	// reconciliation and avoids "stuck queued" after cancel/worker restarts.
	if deps.EnqueueNextDeploymentTask != nil && task.DeploymentID.Valid {
		workspaceID := strings.TrimSpace(task.WorkspaceID)
		deploymentID := strings.TrimSpace(task.DeploymentID.String)
		if workspaceID != "" && deploymentID != "" {
			if nextID, err := taskstore.GetOldestQueuedDeploymentTaskID(ctx, db, workspaceID, deploymentID); err == nil && nextID > 0 {
				ctxKick, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				deps.EnqueueNextDeploymentTask(ctxKick, nextID, workspaceID, deploymentID)
				cancel()
			}
		}
	}

	return nil
}

type noopLogger struct{}

func (noopLogger) Infof(string, ...any)  {}
func (noopLogger) Errorf(string, ...any) {}

