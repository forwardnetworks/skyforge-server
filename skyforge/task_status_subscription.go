package skyforge

import (
	"context"
	"fmt"
	"strings"
	"time"

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

	if task.DeploymentID.Valid {
		t := time.Now().UTC()
		_ = s.updateDeploymentStatus(ctx, task.WorkspaceID, strings.TrimSpace(task.DeploymentID.String), status, &t)
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	// Always nudge task streams.
	_ = notifyTaskUpdatePG(ctx, s.db, task.ID)
	return nil
}
