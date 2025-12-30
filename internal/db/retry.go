package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"encore.dev/rlog"
	"encore.dev/storage/sqldb"
)

// OpenStdlibWithRetry opens the stdlib DB handle with retries for environments
// where the database might not be ready immediately (e.g., container startup).
func OpenStdlibWithRetry(ctx context.Context, sqlDB *sqldb.Database, maxRetries int, initialDelay time.Duration) (*sql.DB, error) {
	var err error
	var stdlib *sql.DB

	for attempt := 1; attempt <= maxRetries; attempt++ {
		stdlib = sqlDB.Stdlib()
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err = stdlib.PingContext(pingCtx)
		cancel()
		if err == nil {
			rlog.Info("Database connection established", "attempt", attempt)
			return stdlib, nil
		}

		rlog.Warn("Database connection attempt failed, retrying...",
			"attempt", attempt,
			"max_retries", maxRetries,
			"error", err,
		)

		if attempt < maxRetries {
			delay := initialDelay * time.Duration(1<<uint(attempt))
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
			rlog.Info("Waiting before retry", "delay_seconds", delay.Seconds(), "next_attempt", attempt+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
}

// WaitForDB waits for the database to be available by attempting a simple query.
func WaitForDB(ctx context.Context, db *sqldb.Database, maxRetries int, initialDelay time.Duration) error {
	time.Sleep(2 * time.Second)
	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := db.Exec(ctx, "SELECT 1")
		if err == nil {
			rlog.Info("Database is available", "attempt", attempt)
			return nil
		}

		rlog.Warn("Database not available yet, retrying...",
			"attempt", attempt,
			"max_retries", maxRetries,
			"error", err,
		)

		if attempt < maxRetries {
			delay := initialDelay * time.Duration(1<<uint(attempt))
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
			rlog.Info("Waiting before retry", "delay_seconds", delay.Seconds(), "next_attempt", attempt+1)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return fmt.Errorf("database not available after %d attempts", maxRetries)
}
