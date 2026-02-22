package tasklocks

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/pglocks"
	"encore.app/internal/taskstore"
	"encore.dev/rlog"
)

// AcquireOrderedTaskLock acquires an advisory lock for a queued task and enforces
// per-deployment/per-user-scope ordering by waiting until the task is the oldest
// queued task for its scope.
//
// The caller must call the returned unlock function.
func AcquireOrderedTaskLock(ctx context.Context, db *sql.DB, task *taskstore.TaskRecord) (unlock func(), err error) {
	if db == nil || task == nil {
		return func() {}, nil
	}
	if !strings.EqualFold(strings.TrimSpace(task.Status), "queued") {
		return func() {}, nil
	}

	unlock = func() {}

	userScopeID := strings.TrimSpace(task.UserScopeID)
	if userScopeID == "" {
		return func() {}, nil
	}

	deploymentID := ""
	if task.DeploymentID.Valid {
		deploymentID = strings.TrimSpace(task.DeploymentID.String)
	}

	sleep := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(750 * time.Millisecond):
			return nil
		}
	}

	if deploymentID != "" {
		lockKey := pglocks.DeploymentAdvisoryLockKey(userScopeID, deploymentID)
		for {
			ok, err := pglocks.TryAdvisoryLock(ctx, db, lockKey)
			if err != nil {
				rlog.Error("deployment lock error", "err", err)
				if err := sleep(); err != nil {
					return func() {}, err
				}
				continue
			}
			if !ok {
				if err := sleep(); err != nil {
					return func() {}, err
				}
				continue
			}

			oldestQueuedID, err := taskstore.GetOldestQueuedDeploymentTaskID(ctx, db, userScopeID, deploymentID)
			if err != nil {
				_ = pglocks.AdvisoryUnlock(context.Background(), db, lockKey)
				rlog.Error("deployment queue check error", "err", err)
				if err := sleep(); err != nil {
					return func() {}, err
				}
				continue
			}
			if oldestQueuedID != 0 && oldestQueuedID != task.ID {
				_ = pglocks.AdvisoryUnlock(context.Background(), db, lockKey)
				if err := sleep(); err != nil {
					return func() {}, err
				}
				continue
			}

			unlock = func() { _ = pglocks.AdvisoryUnlock(context.Background(), db, lockKey) }
			return unlock, nil
		}
	}

	lockKey := pglocks.UserScopeAdvisoryLockKey(userScopeID)
	for {
		ok, err := pglocks.TryAdvisoryLock(ctx, db, lockKey)
		if err != nil {
			rlog.Error("user-scope lock error", "err", err)
			if err := sleep(); err != nil {
				return func() {}, err
			}
			continue
		}
		if !ok {
			if err := sleep(); err != nil {
				return func() {}, err
			}
			continue
		}

		oldestQueuedID, err := taskstore.GetOldestQueuedUserScopeTaskID(ctx, db, userScopeID)
		if err != nil {
			_ = pglocks.AdvisoryUnlock(context.Background(), db, lockKey)
			rlog.Error("user-scope queue check error", "err", err)
			if err := sleep(); err != nil {
				return func() {}, err
			}
			continue
		}
		if oldestQueuedID != 0 && oldestQueuedID != task.ID {
			_ = pglocks.AdvisoryUnlock(context.Background(), db, lockKey)
			if err := sleep(); err != nil {
				return func() {}, err
			}
			continue
		}

		unlock = func() { _ = pglocks.AdvisoryUnlock(context.Background(), db, lockKey) }
		return unlock, nil
	}
}
