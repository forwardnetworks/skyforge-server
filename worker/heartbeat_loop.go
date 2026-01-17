package worker

import (
	"context"
	"strings"
	"time"

	"encore.app/internal/taskheartbeats"
	"encore.dev/rlog"
)

func init() {
	// In Encore Cloud, cron jobs run automatically. In self-hosted deployments,
	// cron is often not configured, which would make task-workers appear "down".
	//
	// Keep the cron-based heartbeat endpoint, but also emit a best-effort
	// heartbeat loop from the worker service itself so status is accurate.
	if !workerEncoreCfg.TaskWorkerEnabled {
		return
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			ctx := context.Background()
			instance := taskheartbeats.WorkerInstanceName()
			if strings.TrimSpace(instance) != "" {
				stdlib, err := getWorkerDB(ctx)
				if err != nil {
					rlog.Error("worker heartbeat loop db error", "err", err)
				} else if err := taskheartbeats.UpsertWorkerHeartbeatForInstance(ctx, stdlib, instance); err != nil {
					rlog.Error("worker heartbeat loop upsert error", "err", err)
				}
			}

			<-ticker.C
		}
	}()
}

