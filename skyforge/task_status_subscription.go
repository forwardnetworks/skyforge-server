package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"encore.app/internal/taskqueue"
	"encore.dev/pubsub"
)

var _ = pubsub.NewSubscription(taskqueue.StatusTopic, "skyforge-task-status-handler", pubsub.SubscriptionConfig[*taskqueue.TaskStatusEvent]{
	Handler: pubsub.MethodHandler((*Service).handleTaskStatus),
})

func (s *Service) handleTaskStatus(ctx context.Context, msg *taskqueue.TaskStatusEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	if msg == nil || msg.TaskID <= 0 {
		return nil
	}
	task, err := getTask(ctx, s.db, msg.TaskID)
	if err != nil {
		// Stale status event for a task that no longer exists (for example: user
		// deleted the deployment while work was queued). Treat as ack to avoid
		// retry loops that can starve other subscriptions.
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if task == nil {
		return nil
	}
	status := strings.TrimSpace(msg.Status)
	errMsg := strings.TrimSpace(msg.Error)

	_ = s.notifyTaskEvent(ctx, task, status, errMsg)

	// Note: worker updates sf_deployments status directly now.
	// Note: notifyTaskUpdatePG and notifyDashboardUpdatePG are handled via AppendTaskEvent.
	return nil
}
