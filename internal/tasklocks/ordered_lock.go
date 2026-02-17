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
// per-deployment/per-owner ordering by waiting until the task is the oldest
// queued task for its owner context.
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

	ownerID := strings.TrimSpace(task.OwnerID)
	if ownerID == "" {
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
		lockKey := pglocks.DeploymentAdvisoryLockKey(ownerID, deploymentID)
		for {
			lock, ok, err := pglocks.TryAdvisoryLock(ctx, db, lockKey)
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

			oldestQueuedID, err := taskstore.GetOldestQueuedDeploymentTaskID(ctx, db, ownerID, deploymentID)
			if err != nil {
				_ = lock.Unlock(context.Background())
				rlog.Error("deployment queue check error", "err", err)
				if err := sleep(); err != nil {
					return func() {}, err
				}
				continue
			}
			if oldestQueuedID != 0 && oldestQueuedID != task.ID {
				_ = lock.Unlock(context.Background())
				if err := sleep(); err != nil {
					return func() {}, err
				}
				continue
			}

			unlock = func() { _ = lock.Unlock(context.Background()) }
			return unlock, nil
		}
	}

	lockKey := pglocks.UserAdvisoryLockKey(ownerID)
	for {
		lock, ok, err := pglocks.TryAdvisoryLock(ctx, db, lockKey)
		if err != nil {
			rlog.Error("owner lock error", "err", err)
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

		oldestQueuedID, err := taskstore.GetOldestQueuedOwnerTaskID(ctx, db, ownerID)
		if err != nil {
			_ = lock.Unlock(context.Background())
			rlog.Error("owner queue check error", "err", err)
			if err := sleep(); err != nil {
				return func() {}, err
			}
			continue
		}
		if oldestQueuedID != 0 && oldestQueuedID != task.ID {
			_ = lock.Unlock(context.Background())
			if err := sleep(); err != nil {
				return func() {}, err
			}
			continue
		}

		unlock = func() { _ = lock.Unlock(context.Background()) }
		return unlock, nil
	}
}
