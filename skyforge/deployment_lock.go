package skyforge

import (
	"context"
	"database/sql"

	"encore.app/internal/pglocks"
)

func deploymentAdvisoryLockKey(userScopeID, deploymentID string) int64 {
	return pglocks.DeploymentAdvisoryLockKey(userScopeID, deploymentID)
}

func userScopeAdvisoryLockKey(userScopeID string) int64 {
	return pglocks.UserScopeAdvisoryLockKey(userScopeID)
}

func pgTryAdvisoryLock(ctx context.Context, db *sql.DB, key int64) (bool, error) {
	return pglocks.TryAdvisoryLock(ctx, db, key)
}

func pgAdvisoryUnlock(ctx context.Context, db *sql.DB, key int64) error {
	return pglocks.AdvisoryUnlock(ctx, db, key)
}
