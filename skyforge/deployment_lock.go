package skyforge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
)

func deploymentAdvisoryLockKey(workspaceID, deploymentID string) int64 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", workspaceID, deploymentID)))
	u := binary.LittleEndian.Uint64(sum[:8])
	return int64(u)
}

func workspaceAdvisoryLockKey(workspaceID string) int64 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:__workspace__", workspaceID)))
	u := binary.LittleEndian.Uint64(sum[:8])
	return int64(u)
}

func pgTryAdvisoryLock(ctx context.Context, db *sql.DB, key int64) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("db unavailable")
	}
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func pgAdvisoryUnlock(ctx context.Context, db *sql.DB, key int64) error {
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&ok); err != nil {
		return err
	}
	return nil
}
