package skyforge

import (
	"context"
	"database/sql"

	"encore.app/internal/pglocks"
)

func deploymentAdvisoryLockKey(ownerID, deploymentID string) int64 {
	return pglocks.DeploymentAdvisoryLockKey(ownerID, deploymentID)
}

func ownerAdvisoryLockKey(ownerID string) int64 {
	return pglocks.UserAdvisoryLockKey(ownerID)
}

func pgTryAdvisoryLock(ctx context.Context, db *sql.DB, key int64) (*pglocks.AdvisoryLock, bool, error) {
	return pglocks.TryAdvisoryLock(ctx, db, key)
}

func pgAdvisoryUnlock(ctx context.Context, lock *pglocks.AdvisoryLock) error {
	if lock == nil {
		return nil
	}
	return lock.Unlock(ctx)
}
