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
		// Heartbeats are emitted by worker instances on a 1-minute cadence.
		n, err := countRecentTaskWorkerHeartbeats(ctx, db, 2*time.Minute+15*time.Second)
		if err == nil {
			return n
		}
	}

	return 0
}

func taskWorkerInstanceName() string {
	instance := strings.TrimSpace(os.Getenv("POD_NAME"))
	if instance == "" {
		instance = strings.TrimSpace(os.Getenv("HOSTNAME"))
	}
	if instance == "" {
		if h, err := os.Hostname(); err == nil {
			instance = strings.TrimSpace(h)
		}
	}
	return instance
}

func (s *Service) UpsertTaskWorkerHeartbeat(ctx context.Context) error {
	if s == nil || s.db == nil || !s.cfg.TaskWorkerEnabled {
		return nil
	}
	instance := taskWorkerInstanceName()
	if instance == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	if err := upsertTaskWorkerHeartbeat(ctxReq, s.db, instance, time.Now()); err != nil {
		return err
	}
	rlog.Debug("task worker heartbeat upserted", "instance", instance)
	return nil
}
