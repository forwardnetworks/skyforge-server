package skyforge

import (
	"context"
	"database/sql"

	"encore.app/internal/pglocks"
)

func deploymentAdvisoryLockKey(workspaceID, deploymentID string) int64 {
	return pglocks.DeploymentAdvisoryLockKey(workspaceID, deploymentID)
}

func workspaceAdvisoryLockKey(workspaceID string) int64 {
	return pglocks.WorkspaceAdvisoryLockKey(workspaceID)
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
