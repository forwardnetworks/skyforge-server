package worker

import (
	"context"
	"strings"
	"time"

	"encore.app/internal/maintenance"
	"encore.app/skyforge"
	"encore.dev/pubsub"
	"encore.dev/rlog"
)

var maintenanceSubscription = pubsub.NewSubscription(maintenance.Topic, "skyforge-maintenance-worker", pubsub.SubscriptionConfig[*maintenance.MaintenanceEvent]{
	Handler:        pubsub.MethodHandler((*Service).handleMaintenanceEvent),
	MaxConcurrency: 1,
	AckDeadline:    10 * time.Minute,
})

func (s *Service) handleMaintenanceEvent(ctx context.Context, msg *maintenance.MaintenanceEvent) error {
	if msg == nil {
		return nil
	}
	if !workerEncoreCfg.TaskWorkerEnabled {
		return nil
	}
	kind := strings.TrimSpace(msg.Kind)
	if kind == "" {
		return nil
	}
	if err := skyforge.InternalRunMaintenance(ctx, &skyforge.InternalRunMaintenanceParams{Kind: kind}); err != nil {
		rlog.Error("maintenance run failed", "kind", kind, "err", err)
		return err
	}
	return nil
}
