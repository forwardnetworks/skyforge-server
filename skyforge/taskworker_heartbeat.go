package skyforge

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"time"

	"encore.dev/rlog"
)

func countTaskWorkerHeartbeats(cfg Config, db *sql.DB) int {
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		n, err := countRecentTaskWorkerHeartbeats(ctx, db, 45*time.Second)
		if err == nil {
			return n
		}
	}

	return 0
}

func startTaskWorkerHeartbeat(cfg Config, db *sql.DB) {
	if !cfg.TaskWorkerEnabled || db == nil {
		return
	}
	instance := strings.TrimSpace(os.Getenv("POD_NAME"))
	if instance == "" {
		instance = strings.TrimSpace(os.Getenv("HOSTNAME"))
	}
	if instance == "" {
		if h, err := os.Hostname(); err == nil {
			instance = strings.TrimSpace(h)
		}
	}

	// Keep this lightweight: a small write every 15s.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			_ = upsertTaskWorkerHeartbeat(ctx, db, instance, time.Now())
			cancel()
			select {
			case <-ticker.C:
				continue
			}
		}
	}()
	rlog.Info("task worker heartbeat enabled", "instance", instance)
}
