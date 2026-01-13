package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/cron"
	"encore.dev/pubsub"
)

type taskEnqueuedEvent struct {
	// Key preserves per-deployment ordering best-effort.
	Key string `json:"key,omitempty" pubsub-attr:"key"`
	// TaskID is the sf_tasks.id being queued.
	TaskID int `json:"taskId"`
}

var taskQueueTopic = pubsub.NewTopic[*taskEnqueuedEvent]("skyforge-task-queue", pubsub.TopicConfig{
	DeliveryGuarantee: pubsub.AtLeastOnce,
	OrderingAttribute: "key",
})

var _ = pubsub.NewSubscription(taskQueueTopic, "skyforge-task-worker", pubsub.SubscriptionConfig[*taskEnqueuedEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleTaskEnqueued),
	MaxConcurrency: 8,
	// Tasks can be long-running (netlab/terraform). Keep ack generous.
	AckDeadline: 2 * time.Hour,
})

// Reconcile queued tasks periodically so they aren't stranded if a publish fails
// or the server restarts mid-request.
var _ = cron.NewJob("skyforge-reconcile-queued-tasks", cron.JobConfig{
	Title:    "Requeue queued Skyforge tasks",
	Every:    1 * cron.Minute,
	Endpoint: ReconcileQueuedTasks,
})

// ReconcileQueuedTasks republishes queue events for tasks stuck in the "queued" state.
//
//encore:api private method=POST path=/internal/tasks/reconcile
func ReconcileQueuedTasks(ctx context.Context) error {
	if defaultService == nil || defaultService.db == nil {
		return nil
	}
	db := defaultService.db
	rows, err := db.QueryContext(ctx, `SELECT id, workspace_id, deployment_id
FROM sf_tasks
WHERE status='queued'
ORDER BY id ASC
LIMIT 200`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type queued struct {
		id           int
		workspaceID  string
		deploymentID sql.NullString
	}
	items := make([]queued, 0, 128)
	for rows.Next() {
		var q queued
		if err := rows.Scan(&q.id, &q.workspaceID, &q.deploymentID); err != nil {
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
		if _, err := taskQueueTopic.Publish(ctx, &taskEnqueuedEvent{TaskID: q.id, Key: key}); err != nil {
			log.Printf("task reconcile publish failed: task=%d err=%v", q.id, err)
		}
	}

	return nil
}

func (s *Service) enqueueTask(ctx context.Context, task *TaskRecord) {
	if s == nil || task == nil || task.ID <= 0 {
		return
	}
	key := strings.TrimSpace(task.WorkspaceID)
	if task.DeploymentID.Valid && strings.TrimSpace(task.DeploymentID.String) != "" {
		key = fmt.Sprintf("%s:%s", strings.TrimSpace(task.WorkspaceID), strings.TrimSpace(task.DeploymentID.String))
	}
	if _, err := taskQueueTopic.Publish(ctx, &taskEnqueuedEvent{TaskID: task.ID, Key: key}); err != nil {
		log.Printf("task enqueue publish failed: task=%d err=%v", task.ID, err)
	}
}

func (s *Service) handleTaskEnqueued(ctx context.Context, msg *taskEnqueuedEvent) error {
	if s == nil || s.db == nil || msg == nil || msg.TaskID <= 0 {
		return nil
	}
	if !s.cfg.TaskWorkerEnabled {
		return nil
	}
	return s.processQueuedTask(ctx, msg.TaskID)
}
