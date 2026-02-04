package worker

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"encore.app/internal/skyforgeconfig"
	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskengine"
	"encore.app/internal/taskexec"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskreconcile"
	"encore.app/internal/taskstore"
	"encore.app/worker/taskrunner"
	"encore.dev/config"
	"encore.dev/pubsub"
	"encore.dev/rlog"
)

//encore:service
type Service struct{}

var (
	workerCoreCfg     skyforgecore.Config
	workerCoreCfgOnce sync.Once
)

// workerEncoreCfg provides access to the Encore-managed config defaults (subset for worker).
var workerEncoreCfg = config.Load[skyforgeconfig.WorkerConfig]()

func getWorkerCoreCfg() skyforgecore.Config {
	workerCoreCfgOnce.Do(func() {
		sec := getSecrets()
		workerCoreCfg = skyforgeconfig.LoadWorkerConfig(workerEncoreCfg, sec)
	})
	return workerCoreCfg
}

var taskQueueSubscription = pubsub.NewSubscription(taskqueue.InteractiveTopic, "skyforge-task-worker", pubsub.SubscriptionConfig[*taskqueue.TaskEnqueuedEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleInteractiveTaskEnqueued),
	MaxConcurrency: 8,
	// Handler must ack quickly; long-running work happens in a DB-backed runner.
	AckDeadline: 30 * time.Second,
})

var taskQueueBackgroundSubscription = pubsub.NewSubscription(taskqueue.BackgroundTopic, "skyforge-task-worker-background", pubsub.SubscriptionConfig[*taskqueue.TaskEnqueuedEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleBackgroundTaskEnqueued),
	MaxConcurrency: 2,
	AckDeadline:    30 * time.Second,
})

func init() {
	go func() {
		// Give the process a moment to start up (config, DB, etc.) before polling.
		time.Sleep(10 * time.Second)
		runQueuedTaskFallbackLoop()
	}()
}

var (
	interactiveRunner *taskrunner.Runner
	backgroundRunner  *taskrunner.Runner
)

func init() {
	exec := func(ctx context.Context, taskID int) error {
		stdlib, err := getWorkerDB(ctx)
		if err != nil {
			return err
		}
		return taskexec.ProcessQueuedTask(ctx, stdlib, taskID, taskexec.Deps{
			Dispatch: func(ctx context.Context, task *taskstore.TaskRecord, log taskexec.Logger) error {
				eng := taskengine.New(getWorkerCoreCfg(), stdlib)
				taskLog := taskDBLogger{db: stdlib, taskID: task.ID}
				if handled, err := eng.DispatchTask(ctx, task, taskLog); handled {
					return err
				}
				return fmt.Errorf("unsupported task type: %s", strings.TrimSpace(task.TaskType))
			},
			Notify: func(ctx context.Context, task *taskstore.TaskRecord, status string, errMsg string) error {
				_, err := taskqueue.StatusTopic.Publish(ctx, &taskqueue.TaskStatusEvent{
					TaskID: task.ID,
					Status: status,
					Error:  errMsg,
				})
				return err
			},
			UpdateDeploymentStatus: func(ctx context.Context, workspaceID string, deploymentID string, status string, finishedAt time.Time) error {
				return taskstore.UpdateDeploymentStatus(ctx, stdlib, workspaceID, deploymentID, status, &finishedAt)
			},
			EnqueueNextDeploymentTask: func(ctx context.Context, nextTaskID int, workspaceID string, deploymentID string) {
				key := strings.TrimSpace(workspaceID)
				if strings.TrimSpace(deploymentID) != "" {
					key = fmt.Sprintf("%s:%s", strings.TrimSpace(workspaceID), strings.TrimSpace(deploymentID))
				}
				ev := &taskqueue.TaskEnqueuedEvent{TaskID: nextTaskID, Key: key}
				priority := 0
				if p := getTaskPriority(ctx, stdlib, nextTaskID); p != 0 {
					priority = p
				}
				if priority < taskstore.PriorityInteractive {
					_, _ = taskqueue.BackgroundTopic.Publish(ctx, ev)
					return
				}
				_, _ = taskqueue.InteractiveTopic.Publish(ctx, ev)
			},
		}, rlogLogger{})
	}

	interactiveRunner = taskrunner.New("interactive", 8, 64, exec)
	backgroundRunner = taskrunner.New("background", 2, 16, exec)
}

func runQueuedTaskFallbackLoop() {
	// This process-level fallback loop exists for self-hosted deployments where Encore cron
	// jobs are not wired up. Without this, a missed Pub/Sub enqueue event can leave tasks
	// stuck in "queued" indefinitely.
	//
	// The loop is intentionally conservative:
	// - only considers tasks that have been queued for at least minAge
	// - at most one queued task per (workspace, deployment) key
	// - low concurrency so we don't stampede the DB / task locks
	if role := strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_ROLE"))); role != "" && role != "worker" {
		return
	}
	if !workerEncoreCfg.TaskWorkerEnabled {
		return
	}

	sem := make(chan struct{}, 2)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	const limit = 50
	minAge := 20 * time.Second

	for range ticker.C {
		if role := strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_ROLE"))); role != "" && role != "worker" {
			return
		}
		if !workerEncoreCfg.TaskWorkerEnabled {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stdlib, err := getWorkerDB(ctx)
		cancel()
		if err != nil {
			rlog.Error("queued task fallback: db unavailable", "err", err)
			continue
		}

		ctxList, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		items, err := taskreconcile.ListStuckQueuedTasksByKey(ctxList, stdlib, limit, minAge)
		cancel()
		if err != nil {
			rlog.Error("queued task fallback: list failed", "err", err)
			continue
		}
		if len(items) == 0 {
			continue
		}

		for _, item := range items {
			if item.TaskID <= 0 || strings.TrimSpace(item.Key) == "" {
				continue
			}
			select {
			case sem <- struct{}{}:
				go func(taskID int, key string) {
					defer func() { <-sem }()
					// Prefer interactive runner for fallback, it handles both task types via DB priority.
					if err := interactiveRunner.Submit(taskID); err != nil {
						rlog.Error("queued task fallback: submit failed", "task_id", taskID, "err", err)
					}
				}(item.TaskID, item.Key)
			default:
				// At concurrency limit; remaining items will be retried on the next tick.
				break
			}
		}
	}
}

func (s *Service) handleInteractiveTaskEnqueued(ctx context.Context, msg *taskqueue.TaskEnqueuedEvent) error {
	return s.submitTask(ctx, msg, interactiveRunner)
}

func (s *Service) handleBackgroundTaskEnqueued(ctx context.Context, msg *taskqueue.TaskEnqueuedEvent) error {
	return s.submitTask(ctx, msg, backgroundRunner)
}

func (s *Service) submitTask(ctx context.Context, msg *taskqueue.TaskEnqueuedEvent, r *taskrunner.Runner) error {
	// IMPORTANT: Only the dedicated worker deployment should process tasks.
	// If a non-worker pod accidentally includes worker subscriptions, it must not ack messages
	// (otherwise tasks can appear "queued forever"). Returning an error causes Pub/Sub redelivery.
	if role := strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_ROLE"))); role != "" && role != "worker" {
		return fmt.Errorf("task worker invoked in non-worker role=%q", role)
	}
	if !workerEncoreCfg.TaskWorkerEnabled {
		// Treat as ack: when workers are disabled we should not endlessly redeliver.
		return nil
	}
	if msg == nil || msg.TaskID <= 0 {
		return nil
	}
	if r == nil {
		return fmt.Errorf("task runner not configured")
	}
	// ACK quickly: execution happens asynchronously in the DB-backed runner.
	if err := r.Submit(msg.TaskID); err != nil {
		rlog.Error("task enqueue: runner submit failed", "task_id", msg.TaskID, "err", err)
		return err
	}
	return nil
}

type rlogLogger struct{}

func (rlogLogger) Infof(format string, args ...any)  { rlog.Info(fmt.Sprintf(format, args...)) }
func (rlogLogger) Errorf(format string, args ...any) { rlog.Error(fmt.Sprintf(format, args...)) }

type taskDBLogger struct {
	db     *sql.DB
	taskID int
}

func (l taskDBLogger) Infof(format string, args ...any) {
	l.append("stdout", fmt.Sprintf(format, args...))
}

func (l taskDBLogger) Errorf(format string, args ...any) {
	l.append("stderr", fmt.Sprintf(format, args...))
}

func (l taskDBLogger) append(stream string, msg string) {
	if l.db == nil || l.taskID <= 0 {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	if len(msg) > 1<<20 {
		msg = msg[:1<<20]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = taskstore.AppendTaskLog(ctx, l.db, l.taskID, stream, msg)
	if stream == "stderr" {
		rlog.Error(msg, "task_id", l.taskID)
		return
	}
	rlog.Info(msg, "task_id", l.taskID)
}

func getTaskPriority(ctx context.Context, db *sql.DB, taskID int) int {
	if db == nil || taskID <= 0 {
		return 0
	}
	var p sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT priority FROM sf_tasks WHERE id=$1`, taskID).Scan(&p); err != nil || !p.Valid {
		return 0
	}
	return int(p.Int64)
}
