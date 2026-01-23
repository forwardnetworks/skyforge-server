package skyforge

import (
	"context"
	"fmt"
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
		return err
	}
	if task == nil {
		return fmt.Errorf("task not found")
	}
	status := strings.TrimSpace(msg.Status)
	errMsg := strings.TrimSpace(msg.Error)

	_ = s.notifyTaskEvent(ctx, task, status, errMsg)

	// Note: worker updates sf_deployments status directly now.
	// Note: notifyTaskUpdatePG and notifyDashboardUpdatePG are handled via AppendTaskEvent.
	return nil
}
