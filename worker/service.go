package worker

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"encore.app/internal/skyforgeconfig"
	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskengine"
	"encore.app/internal/taskexec"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskstore"
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
	Handler:        pubsub.MethodHandler((*Service).handleTaskEnqueued),
	MaxConcurrency: 8,
	// Tasks can be long-running (netlab/terraform). Keep ack generous.
	AckDeadline: 2 * time.Hour,
})

var taskQueueBackgroundSubscription = pubsub.NewSubscription(taskqueue.BackgroundTopic, "skyforge-task-worker-background", pubsub.SubscriptionConfig[*taskqueue.TaskEnqueuedEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleTaskEnqueued),
	MaxConcurrency: 2,
	AckDeadline:    2 * time.Hour,
})

func (s *Service) handleTaskEnqueued(ctx context.Context, msg *taskqueue.TaskEnqueuedEvent) error {
	if msg == nil || msg.TaskID <= 0 {
		return nil
	}
	stdlib, err := getWorkerDB(ctx)
	if err != nil {
		return err
	}
	return taskexec.ProcessQueuedTask(ctx, stdlib, msg.TaskID, taskexec.Deps{
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
