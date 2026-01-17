package taskheartbeats

import (
	"context"
	"database/sql"
	"time"
)

func upsertTaskWorkerHeartbeat(ctx context.Context, db *sql.DB, instance string, at time.Time) error {
	if db == nil {
		return sql.ErrConnDone
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_taskworker_heartbeats (instance, last_seen)
VALUES ($1, $2)
ON CONFLICT (instance)
DO UPDATE SET last_seen = EXCLUDED.last_seen
`, instance, at.UTC())
	return err
}

func countRecentTaskWorkerHeartbeats(ctx context.Context, db *sql.DB, since time.Duration) (int, error) {
	if db == nil {
		return 0, sql.ErrConnDone
	}
	cutoff := time.Now().UTC().Add(-since)
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_taskworker_heartbeats WHERE last_seen >= $1`, cutoff).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

