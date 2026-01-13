package skyforge

import (
	"context"
	"time"
)

func (s *Service) runWithAdvisoryLock(ctx context.Context, key int64, fn func(context.Context) error) error {
	if s == nil || s.db == nil || fn == nil {
		return nil
	}
	db := s.db

	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var locked bool
	if err := db.QueryRowContext(ctxReq, `SELECT pg_try_advisory_lock($1)`, key).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		// Another worker is already running this task; treat as success.
		return nil
	}
	defer func() {
		ctxUnlock, cancelUnlock := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelUnlock()
		var unlocked bool
		_ = db.QueryRowContext(ctxUnlock, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked)
	}()

	return fn(ctx)
}
