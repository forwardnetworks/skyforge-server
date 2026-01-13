package skyforge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/maintenance"
	"encore.dev/pubsub"
	"encore.dev/rlog"
)

var maintenanceSubscription = pubsub.NewSubscription(maintenance.Topic, "skyforge-maintenance-worker", pubsub.SubscriptionConfig[*maintenance.MaintenanceEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleMaintenanceEvent),
	MaxConcurrency: 1,
	AckDeadline:    10 * time.Minute,
})

func (s *Service) handleMaintenanceEvent(ctx context.Context, msg *maintenance.MaintenanceEvent) error {
	if s == nil || s.db == nil || msg == nil {
		return nil
	}
	if !s.cfg.TaskWorkerEnabled {
		// NACK (return error) so non-worker pods do not ACK maintenance messages.
		return fmt.Errorf("task worker disabled")
	}

	kind := strings.TrimSpace(msg.Kind)
	switch kind {
	case "reconcile_queued":
		return s.runWithAdvisoryLock(ctx, 74001, func(ctx context.Context) error {
			ctxReq, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return reconcileQueuedTasks(ctxReq, s)
		})
	case "reconcile_running":
		return s.runWithAdvisoryLock(ctx, 74002, func(ctx context.Context) error {
			ctxReq, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			return reconcileRunningTasks(ctxReq, s)
		})
	case "queue_metrics":
		return s.runWithAdvisoryLock(ctx, 74003, func(ctx context.Context) error {
			ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return s.updateTaskQueueMetrics(ctxReq)
		})
	default:
		rlog.Info("maintenance: ignoring unknown job kind", "kind", kind)
		return nil
	}
}
