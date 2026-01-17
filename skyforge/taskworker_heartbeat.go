package skyforge

import (
	"context"
	"database/sql"
	"time"

	"encore.app/internal/taskheartbeats"
)

func countTaskWorkerHeartbeats(cfg Config, db *sql.DB) int {
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// Heartbeats are emitted by worker instances on a 1-minute cadence.
		n, err := taskheartbeats.CountWorkerHeartbeats(ctx, db, 2*time.Minute+15*time.Second)
		if err == nil {
			return n
		}
	}

	return 0
}
