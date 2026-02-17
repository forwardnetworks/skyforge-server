package skyforge

import (
	"context"
	"database/sql"

	"encore.app/internal/pglocks"
)

func deploymentAdvisoryLockKey(userContextID, deploymentID string) int64 {
	return pglocks.DeploymentAdvisoryLockKey(userContextID, deploymentID)
}

func workspaceAdvisoryLockKey(userContextID string) int64 {
	return pglocks.WorkspaceAdvisoryLockKey(userContextID)
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
