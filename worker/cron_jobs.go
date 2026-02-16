package worker

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"encore.app/internal/db"
	"encore.app/internal/skyforgedb"
	"encore.app/internal/taskheartbeats"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskreconcile"
	"encore.app/internal/taskstore"
	"encore.dev/cron"
	"encore.dev/rlog"
)

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
	if role := strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_ROLE"))); role != "" && role != "worker" {
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

var (
	queuePollerOnce sync.Once
	queuePollerSem  chan struct{}
)

func initQueuePollerSem() {
	queuePollerOnce.Do(func() {
		maxConc := workerEncoreCfg.TaskWorkerPollMaxConcurrency
		if maxConc <= 0 {
			maxConc = 4
		}
		if maxConc > 32 {
			maxConc = 32
		}
		queuePollerSem = make(chan struct{}, maxConc)
	})
}

// CronProcessQueuedTasksFallback is a DB-backed fallback that starts tasks directly when they
// appear stuck in "queued".
//
// This avoids the "queued forever" failure mode when Pub/Sub delivery is delayed/unavailable.
// The primary mechanism is still Pub/Sub; this only kicks in after a minimum queued age.
//
//encore:api private method=POST path=/internal/worker/tasks/poll
func CronProcessQueuedTasksFallback(ctx context.Context) error {
	if !workerEncoreCfg.TaskWorkerEnabled {
		return nil
	}
	if !workerEncoreCfg.TaskWorkerPollEnabled {
		return nil
	}
	if role := strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_ROLE"))); role != "" && role != "worker" {
		return nil
	}

	initQueuePollerSem()

	stdlib, err := getWorkerDB(ctx)
	if err != nil {
		return err
	}

	minQueued := time.Duration(workerEncoreCfg.TaskWorkerPollMinQueuedSeconds) * time.Second
	if minQueued < 0 {
		minQueued = 0
	}
	limit := workerEncoreCfg.TaskWorkerPollMaxTasksPerTick
	if limit <= 0 {
		limit = 10
	}
	if limit > 200 {
		limit = 200
	}

	// Only attempt to start tasks that have been queued for at least minQueued.
	ctxList, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	items, err := taskreconcile.ListStuckQueuedTasksByKey(ctxList, stdlib, limit, minQueued)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	for _, item := range items {
		taskID := item.TaskID
		if taskID <= 0 {
			continue
		}
		select {
		case queuePollerSem <- struct{}{}:
			go func() {
				defer func() { <-queuePollerSem }()
				if err := interactiveRunner.Submit(taskID); err != nil {
					rlog.Error("cron poll queued: submit failed", "task_id", taskID, "err", err)
				}
			}()
		default:
			// Poller is at concurrency limit; remaining items will be retried on the next tick.
			return nil
		}
	}
	return nil
}

var _ = cron.NewJob("skyforge-worker-poll-queued", cron.JobConfig{
	Title:    "Fallback poll queued tasks",
	Endpoint: CronProcessQueuedTasksFallback,
	Every:    1 * cron.Minute,
})

// CronReconcileQueuedTasks republishes queue events for tasks stuck in the "queued" state.
//
//encore:api private method=POST path=/internal/worker/tasks/reconcile
func CronReconcileQueuedTasks(ctx context.Context) error {
	if !workerEncoreCfg.TaskWorkerEnabled {
		return nil
	}
	if role := strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_ROLE"))); role != "" && role != "worker" {
		return nil
	}
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
		rlog.Warn("reconcile running task", "task_id", item.TaskID, "owner", item.OwnerID, "deployment", item.DeploymentID)

		if err := taskstore.FinishTask(ctx, stdlib, item.TaskID, "failed", errMsg); err != nil {
			rlog.Error("reconcile running task finish failed", "task_id", item.TaskID, "err", err)
			continue
		}
		if strings.TrimSpace(item.DeploymentID) != "" {
			if err := taskreconcile.UpdateDeploymentStatus(ctx, stdlib, item.OwnerID, item.DeploymentID, "failed", time.Now()); err != nil {
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
