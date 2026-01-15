package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.app/internal/maintenance"
	"encore.dev/rlog"
)

func (s *Service) handleMaintenanceEvent(ctx context.Context, msg *maintenance.MaintenanceEvent) error {
	if s == nil || s.db == nil || msg == nil {
		return nil
	}
	if !s.cfg.TaskWorkerEnabled {
		// If the worker is disabled, ACK maintenance messages to avoid infinite redelivery loops.
		// Tasks will remain queued until a worker is enabled and reconciliation runs.
		rlog.Warn("maintenance: worker disabled; skipping", "kind", strings.TrimSpace(msg.Kind))
		return nil
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
		// Deprecated: metrics refresh is now executed directly by InternalRefreshTaskQueueMetrics
		// so metrics are updated in the skyforge-server process (which is typically scraped).
		return nil
	case "workspace_sync":
		return s.runWithAdvisoryLock(ctx, 74004, func(ctx context.Context) error {
			runWorkspaceSync(s.cfg, s.workspaceStore, s.db)
			return nil
		})
	case "cloud_credential_checks":
		return s.runWithAdvisoryLock(ctx, 74005, func(ctx context.Context) error {
			runCloudCredentialChecks(s.cfg, s.workspaceStore, s.awsStore, s.db)
			return nil
		})
	default:
		rlog.Info("maintenance: ignoring unknown job kind", "kind", kind)
		return nil
	}
}
