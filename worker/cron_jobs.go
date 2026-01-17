package worker

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"encore.app/internal/db"
	"encore.app/internal/skyforgeconfig"
	"encore.app/internal/skyforgedb"
	"encore.app/internal/taskheartbeats"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskreconcile"
	"encore.app/internal/taskstore"
	"encore.dev/config"
	"encore.dev/cron"
	"encore.dev/rlog"
)

var workerEncoreCfg = config.Load[skyforgeconfig.EncoreConfig]()

var (
	workerDBOnce sync.Once
	workerDBErr  error
	workerDBStd  *sql.DB
)

func getWorkerDB(ctx context.Context) (*sql.DB, error) {
	workerDBOnce.Do(func() {
		stdlib, err := db.OpenStdlibWithRetry(ctx, skyforgedb.SkyforgeDB, 10, 250*time.Millisecond)
		if err != nil {
			workerDBErr = err
			return
		}
		workerDBStd = stdlib
	})
	if workerDBErr != nil {
		return nil, workerDBErr
	}
	if workerDBStd == nil {
		return nil, context.Canceled
	}
	return workerDBStd, nil
}

// CronWorkerHeartbeat upserts a task worker heartbeat for this worker instance.
//
// This is used to detect whether any worker pods are alive when tasks are queued.
//
//encore:api private method=POST path=/internal/worker/heartbeat
func CronWorkerHeartbeat(ctx context.Context) error {
	if !workerEncoreCfg.TaskWorkerEnabled {
		return nil
	}
	instance := taskheartbeats.WorkerInstanceName()
	if strings.TrimSpace(instance) == "" {
		return nil
	}
	stdlib, err := getWorkerDB(ctx)
	if err != nil {
		return err
	}
	return taskheartbeats.UpsertWorkerHeartbeatForInstance(ctx, stdlib, instance)
}

var _ = cron.NewJob("skyforge-worker-heartbeat", cron.JobConfig{
	Title:    "Task worker heartbeat",
	Endpoint: CronWorkerHeartbeat,
	Every:    1 * cron.Minute,
})

// NOTE: worker uses the shared Encore-managed database resource directly.

// CronReconcileQueuedTasks republishes queue events for tasks stuck in the "queued" state.
//
//encore:api private method=POST path=/internal/worker/tasks/reconcile
func CronReconcileQueuedTasks(ctx context.Context) error {
	stdlib, err := getWorkerDB(ctx)
	if err != nil {
		return err
	}
	items, err := taskreconcile.ListQueuedTasks(ctx, stdlib, 200)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.TaskID <= 0 || strings.TrimSpace(item.Key) == "" {
			continue
		}
		ev := &taskqueue.TaskEnqueuedEvent{TaskID: item.TaskID, Key: item.Key}
		if item.Priority < taskstore.PriorityInteractive {
			if _, err := taskqueue.BackgroundTopic.Publish(ctx, ev); err != nil {
				rlog.Error("task reconcile publish failed", "task_id", item.TaskID, "err", err)
			}
			continue
		}
		if _, err := taskqueue.InteractiveTopic.Publish(ctx, ev); err != nil {
			rlog.Error("task reconcile publish failed", "task_id", item.TaskID, "err", err)
		}
	}
	return nil
}

var _ = cron.NewJob("skyforge-worker-reconcile-queued", cron.JobConfig{
	Title:    "Reconcile queued tasks",
	Endpoint: CronReconcileQueuedTasks,
	Every:    1 * cron.Minute,
})

// CronReconcileRunningTasks finds long-running tasks that appear stuck and marks them failed.
//
//encore:api private method=POST path=/internal/worker/tasks/reconcile-running
func CronReconcileRunningTasks(ctx context.Context) error {
	stdlib, err := getWorkerDB(ctx)
	if err != nil {
		return err
	}
	items, err := taskreconcile.FindStuckRunningTasks(ctx, stdlib, taskreconcile.RunningReconcileOptions{
		Limit: 50,
	})
	if err != nil {
		return err
	}
	for _, item := range items {
		rec, err := taskstore.GetTask(ctx, stdlib, item.TaskID)
		if err != nil || rec == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rec.Status), "running") {
			continue
		}

		errMsg := "task appears stuck (no recent activity); marked failed by reconciler"
		rlog.Warn("reconcile running task", "task_id", item.TaskID, "workspace", item.WorkspaceID, "deployment", item.DeploymentID)

		if err := taskstore.FinishTask(ctx, stdlib, item.TaskID, "failed", errMsg); err != nil {
			rlog.Error("reconcile running task finish failed", "task_id", item.TaskID, "err", err)
			continue
		}
		if strings.TrimSpace(item.DeploymentID) != "" {
			if err := taskreconcile.UpdateDeploymentStatus(ctx, stdlib, item.WorkspaceID, item.DeploymentID, "failed", time.Now()); err != nil {
				rlog.Error("reconcile running task deployment status failed", "task_id", item.TaskID, "err", err)
			}
		}
		_ = taskstore.AppendTaskLog(context.Background(), stdlib, item.TaskID, "stderr", fmt.Sprintf("[reconciler] %s", errMsg))
	}
	return nil
}

var _ = cron.NewJob("skyforge-worker-reconcile-running", cron.JobConfig{
	Title:    "Reconcile running tasks",
	Endpoint: CronReconcileRunningTasks,
	Every:    10 * cron.Minute,
})
