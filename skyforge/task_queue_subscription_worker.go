//go:build skyforge_worker

package skyforge

import (
	"context"
	"time"

	"encore.dev/pubsub"
)

var _ = pubsub.NewSubscription(taskQueueTopic, "skyforge-task-worker", pubsub.SubscriptionConfig[*taskEnqueuedEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleTaskEnqueued),
	MaxConcurrency: 8,
	// Tasks can be long-running (netlab/terraform). Keep ack generous.
	AckDeadline: 2 * time.Hour,
})

func (s *Service) handleTaskEnqueued(ctx context.Context, msg *taskEnqueuedEvent) error {
	if s == nil || s.db == nil || msg == nil || msg.TaskID <= 0 {
		return nil
	}
	return s.processQueuedTask(ctx, msg.TaskID)
}

