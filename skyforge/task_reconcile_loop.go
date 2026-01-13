package skyforge

import (
	"context"
	"time"

	"encore.dev/rlog"
)

func (s *Service) startTaskReconcileLoops() {
	if s == nil || s.db == nil || !s.cfg.TaskWorkerEnabled {
		return
	}

	go func() {
		interval := 1 * time.Minute
		rlog.Info("task reconcile queued loop enabled", "interval", interval.String())
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			if err := reconcileQueuedTasks(ctx, s); err != nil {
				rlog.Error("task reconcile queued failed", "err", err)
			}
			cancel()
			time.Sleep(interval)
		}
	}()

	go func() {
		interval := 10 * time.Minute
		rlog.Info("task reconcile running loop enabled", "interval", interval.String())
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			if err := reconcileRunningTasks(ctx, s); err != nil {
				rlog.Error("task reconcile running failed", "err", err)
			}
			cancel()
			time.Sleep(interval)
		}
	}()
}
