package skyforge

import (
	"context"
	"strings"

	"encore.app/internal/maintenance"
	"encore.dev/cron"
	"encore.dev/rlog"
)

var _ = cron.NewJob("maintenance-reconcile-queued", cron.JobConfig{
	Title:    "Skyforge: reconcile queued tasks",
	Every:    1 * cron.Minute,
	Endpoint: EnqueueReconcileQueued,
})

var _ = cron.NewJob("maintenance-reconcile-running", cron.JobConfig{
	Title:    "Skyforge: reconcile running tasks",
	Every:    10 * cron.Minute,
	Endpoint: EnqueueReconcileRunning,
})

var _ = cron.NewJob("maintenance-queue-metrics", cron.JobConfig{
	Title:    "Skyforge: refresh task queue metrics",
	Every:    1 * cron.Minute,
	Endpoint: EnqueueQueueMetrics,
})

//encore:api private
func EnqueueReconcileQueued(ctx context.Context) error {
	return enqueueMaintenance(ctx, "reconcile_queued")
}

//encore:api private
func EnqueueReconcileRunning(ctx context.Context) error {
	return enqueueMaintenance(ctx, "reconcile_running")
}

//encore:api private
func EnqueueQueueMetrics(ctx context.Context) error {
	return enqueueMaintenance(ctx, "queue_metrics")
}

func enqueueMaintenance(ctx context.Context, kind string) error {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return nil
	}
	if _, err := maintenance.Topic.Publish(ctx, &maintenance.MaintenanceEvent{Kind: kind}); err != nil {
		rlog.Error("maintenance enqueue failed", "kind", kind, "err", err)
		return err
	}
	return nil
}
