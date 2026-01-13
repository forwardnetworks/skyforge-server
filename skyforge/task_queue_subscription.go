package skyforge

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"encore.app/internal/taskqueue"
	"encore.dev/pubsub"
)

func init() {
	// In Kubernetes we run a dedicated worker Deployment. Avoid registering subscriptions
	// in non-worker pods as they can receive queue messages and NACK them, adding latency.
	//
	// Default behavior (env unset) is enabled for local dev / single-process setups.
	enabled := strings.TrimSpace(os.Getenv("SKYFORGE_TASK_WORKER_ENABLED"))
	if enabled != "" && enabled != "true" {
		return
	}

	_ = pubsub.NewSubscription(taskqueue.Topic, "skyforge-task-worker", pubsub.SubscriptionConfig[*taskqueue.TaskEnqueuedEvent]{
		Handler:        pubsub.MethodHandler((*Service).handleTaskEnqueued),
		MaxConcurrency: 8,
		// Tasks can be long-running (netlab/terraform). Keep ack generous.
		AckDeadline: 2 * time.Hour,
	})
}

func (s *Service) handleTaskEnqueued(ctx context.Context, msg *taskqueue.TaskEnqueuedEvent) error {
	if s == nil || s.db == nil || msg == nil || msg.TaskID <= 0 {
		return nil
	}
	if !s.cfg.TaskWorkerEnabled {
		// NACK (return error) so non-worker pods do not ACK queue messages.
		// Dedicated worker pods should have this enabled to drain the queue.
		return fmt.Errorf("task worker disabled")
	}
	return s.processQueuedTask(ctx, msg.TaskID)
}
