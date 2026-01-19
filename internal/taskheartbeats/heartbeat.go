package taskheartbeats

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"time"

	"encore.dev/rlog"
)

func taskWorkerInstanceName() string {
	instance := strings.TrimSpace(os.Getenv("POD_NAME"))
	if instance == "" {
		instance = strings.TrimSpace(os.Getenv("HOSTNAME"))
	}
	if instance == "" {
		if h, err := os.Hostname(); err == nil {
			instance = strings.TrimSpace(h)
		}
	}
	return instance
}

// WorkerInstanceName returns a stable identifier for the current worker instance.
// It is derived from POD_NAME/HOSTNAME (or os.Hostname as a fallback).
func WorkerInstanceName() string {
	return taskWorkerInstanceName()
}

func UpsertWorkerHeartbeat(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	instance := taskWorkerInstanceName()
	if instance == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	if err := upsertTaskWorkerHeartbeat(ctxReq, db, instance, time.Now()); err != nil {
		return err
	}
	rlog.Debug("task worker heartbeat upserted", "instance", instance)
	return nil
}

// UpsertWorkerHeartbeatForInstance updates the heartbeat for the provided instance name.
//
// This is useful when a service (e.g. skyforge) performs the DB write on behalf of
// a worker, but wants the instance identity to reflect the worker pod, not the API pod.
func UpsertWorkerHeartbeatForInstance(ctx context.Context, db *sql.DB, instance string) error {
	if db == nil {
		return nil
	}
	instance = strings.TrimSpace(instance)
	if instance == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return upsertTaskWorkerHeartbeat(ctxReq, db, instance, time.Now())
}

func CountWorkerHeartbeats(ctx context.Context, db *sql.DB, since time.Duration) (int, error) {
	return countRecentTaskWorkerHeartbeats(ctx, db, since)
}

// MostRecentWorkerHeartbeatAgeSeconds returns the age (in seconds) of the most
// recent observed worker heartbeat. A large value indicates a stalled or absent
// worker fleet.
func MostRecentWorkerHeartbeatAgeSeconds(ctx context.Context, db *sql.DB) (float64, error) {
	return mostRecentTaskWorkerHeartbeatAgeSeconds(ctx, db)
}
