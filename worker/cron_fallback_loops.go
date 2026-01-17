package worker

import (
	"context"
	"database/sql"
	"time"

	"encore.app/internal/pglocks"
	"encore.dev/rlog"
)

func init() {
	// In Encore Cloud, cron jobs run automatically. In self-hosted deployments,
	// cron is often not configured, which can lead to:
	// - stale task queue metrics/health
	// - queued tasks stuck due to missing reconciliation
	// - missing workspace sync / cloud credential checks
	//
	// Keep the cron-based endpoints, but also execute best-effort loops from the
	// worker service itself.
	if !workerEncoreCfg.TaskWorkerEnabled {
		return
	}

	go runLoop("worker-heartbeat", 60*time.Second, func(ctx context.Context, db *sql.DB) error {
		return CronWorkerHeartbeat(ctx)
	})
	go runLeaderLoop("worker-reconcile-queued", 60*time.Second, func(ctx context.Context, db *sql.DB) error {
		return CronReconcileQueuedTasks(ctx)
	})
	go runLeaderLoop("worker-reconcile-running", 10*time.Minute, func(ctx context.Context, db *sql.DB) error {
		return CronReconcileRunningTasks(ctx)
	})
	go runLeaderLoop("worker-workspace-sync", 5*time.Minute, func(ctx context.Context, db *sql.DB) error {
		return CronWorkspaceSync(ctx)
	})
	go runLeaderLoop("worker-cloud-credential-checks", 30*time.Minute, func(ctx context.Context, db *sql.DB) error {
		return CronCloudCredentialChecks(ctx)
	})
}

func runLoop(name string, every time.Duration, fn func(ctx context.Context, db *sql.DB) error) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		ctx := context.Background()
		db, err := getWorkerDB(ctx)
		if err != nil {
			rlog.Error("cron fallback db error", "name", name, "err", err)
		} else if err := fn(ctx, db); err != nil {
			rlog.Error("cron fallback run error", "name", name, "err", err)
		}
		<-ticker.C
	}
}

func runLeaderLoop(name string, every time.Duration, fn func(ctx context.Context, db *sql.DB) error) {
	key := pglocks.KeyFromString("skyforge:" + name)

	runLoop(name, every, func(ctx context.Context, db *sql.DB) error {
		ok, err := pglocks.TryAdvisoryLock(ctx, db, key)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		defer func() {
			_ = pglocks.AdvisoryUnlock(context.Background(), db, key)
		}()
		return fn(ctx, db)
	})
}

