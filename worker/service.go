package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"encore.app/internal/jsonmap"
	"encore.app/internal/skyforgeconfig"
	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskengine"
	"encore.app/internal/taskexec"
	"encore.app/internal/taskqueue"
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
			UpdateDeploymentStatus: func(ctx context.Context, userScopeID string, deploymentID string, status string, finishedAt time.Time) error {
				return taskstore.UpdateDeploymentStatus(ctx, stdlib, userScopeID, deploymentID, status, &finishedAt)
			},
			EnqueueNextDeploymentTask: func(ctx context.Context, nextTaskID int, userScopeID string, deploymentID string) {
				key := strings.TrimSpace(userScopeID)
				if strings.TrimSpace(deploymentID) != "" {
					key = fmt.Sprintf("%s:%s", strings.TrimSpace(userScopeID), strings.TrimSpace(deploymentID))
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
			OnFinished: func(task *taskstore.TaskRecord, status string, startedAt time.Time) {
				if err := enqueueForwardSyncAfterTopologySuccess(context.Background(), stdlib, task, status); err != nil {
					rlog.Warn("forward sync auto-enqueue failed", "task_id", task.ID, "err", err)
				}
			},
		}, rlogLogger{})
	}

	interactiveRunner = taskrunner.New("interactive", 8, 64, exec)
	backgroundRunner = taskrunner.New("background", 2, 16, exec)
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

func enqueueForwardSyncAfterTopologySuccess(ctx context.Context, db *sql.DB, task *taskstore.TaskRecord, status string) error {
	if db == nil || task == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(status), "success") {
		return nil
	}
	if !topologyTaskType(strings.TrimSpace(task.TaskType)) {
		return nil
	}
	if !task.DeploymentID.Valid || strings.TrimSpace(task.DeploymentID.String) == "" {
		return nil
	}
	if !shouldAutoForwardSyncForAction(task.Metadata) {
		return nil
	}

	userScopeID := strings.TrimSpace(task.UserScopeID)
	deploymentID := strings.TrimSpace(task.DeploymentID.String)
	if !deploymentForwardEnabled(ctx, db, userScopeID, deploymentID) {
		return nil
	}

	meta, err := jsonmap.ToJSONMap(map[string]any{
		"deploymentId":  deploymentID,
		"dedupeKey":     fmt.Sprintf("forward-sync:%s:%s", userScopeID, deploymentID),
		"priority":      taskstore.PriorityBackground,
		"triggerTaskId": task.ID,
	})
	if err != nil {
		return err
	}
	forwardTask, err := taskstore.CreateTaskAllowActive(
		ctx,
		db,
		userScopeID,
		&deploymentID,
		"forward-sync",
		fmt.Sprintf("Skyforge Forward sync (%s)", strings.TrimSpace(task.CreatedBy)),
		strings.TrimSpace(task.CreatedBy),
		meta,
	)
	if err != nil || forwardTask == nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(forwardTask.Status), "queued") {
		return nil
	}
	return publishTaskByPriority(ctx, db, forwardTask)
}

func topologyTaskType(taskType string) bool {
	switch strings.ToLower(strings.TrimSpace(taskType)) {
	case "netlab-c9s-run", "clabernetes-run", "containerlab-run", "netlab-run", "eve-ng-run":
		return true
	default:
		return false
	}
}

func shouldAutoForwardSyncForAction(meta taskstore.JSONMap) bool {
	if meta == nil {
		return true
	}
	metaMap, err := jsonmap.FromJSONMap(meta)
	if err != nil {
		return true
	}
	action := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", metaMap["action"])))
	if action == "" {
		if raw, ok := metaMap["spec"]; ok {
			if m, ok := raw.(map[string]any); ok {
				action = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", m["action"])))
			}
		}
	}
	switch action {
	case "", "deploy", "start", "up", "create", "apply", "run":
		return true
	default:
		return false
	}
}

func deploymentForwardEnabled(ctx context.Context, db *sql.DB, userScopeID, deploymentID string) bool {
	if db == nil || userScopeID == "" || deploymentID == "" {
		return false
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var raw []byte
	if err := db.QueryRowContext(ctxReq, `SELECT config FROM sf_deployments WHERE user_id=$1 AND id=$2`, userScopeID, deploymentID).Scan(&raw); err != nil {
		return false
	}
	cfg := map[string]any{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false
	}
	switch v := cfg["forwardEnabled"].(type) {
	case bool:
		return v
	case string:
		s := strings.TrimSpace(v)
		return strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes")
	default:
		return false
	}
}

func publishTaskByPriority(ctx context.Context, db *sql.DB, task *taskstore.TaskRecord) error {
	if task == nil || task.ID <= 0 {
		return nil
	}
	key := strings.TrimSpace(task.UserScopeID)
	if task.DeploymentID.Valid && strings.TrimSpace(task.DeploymentID.String) != "" {
		key = fmt.Sprintf("%s:%s", strings.TrimSpace(task.UserScopeID), strings.TrimSpace(task.DeploymentID.String))
	}
	ev := &taskqueue.TaskEnqueuedEvent{TaskID: task.ID, Key: key}
	priority := task.Priority
	if priority == 0 {
		priority = getTaskPriority(ctx, db, task.ID)
	}
	if priority < taskstore.PriorityInteractive {
		_, err := taskqueue.BackgroundTopic.Publish(ctx, ev)
		return err
	}
	_, err := taskqueue.InteractiveTopic.Publish(ctx, ev)
	return err
}
