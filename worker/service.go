package worker

import (
	"context"
	"fmt"
	"time"

	"encore.app/internal/maintenance"
	"encore.app/internal/taskqueue"
	"encore.app/skyforge"
	"encore.dev/pubsub"
)

//encore:service
type Service struct{}

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

var maintenanceSubscription = pubsub.NewSubscription(maintenance.Topic, "skyforge-maintenance-worker", pubsub.SubscriptionConfig[*maintenance.MaintenanceEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleMaintenanceEvent),
	MaxConcurrency: 1,
	AckDeadline:    10 * time.Minute,
})

func (s *Service) handleTaskEnqueued(ctx context.Context, msg *taskqueue.TaskEnqueuedEvent) error {
	if msg == nil || msg.TaskID <= 0 {
		return nil
	}
	core := skyforge.DefaultService()
	if core == nil {
		return fmt.Errorf("skyforge service not initialized")
	}
	// Only worker deployments should run this service; keep the guard for safety.
	if !core.TaskWorkerEnabled() {
		return nil
	}
	return core.ProcessQueuedTask(ctx, msg.TaskID)
}

func (s *Service) handleMaintenanceEvent(ctx context.Context, msg *maintenance.MaintenanceEvent) error {
	if msg == nil {
		return nil
	}
	core := skyforge.DefaultService()
	if core == nil {
		return fmt.Errorf("skyforge service not initialized")
	}
	if !core.TaskWorkerEnabled() {
		return nil
	}
	return core.HandleMaintenanceEvent(ctx, msg)
}
