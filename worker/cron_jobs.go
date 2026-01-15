package worker

import (
	"context"

	"encore.app/skyforge"
	"encore.dev/cron"
)

// CronWorkerHeartbeat upserts a task worker heartbeat for this worker instance.
//
// This is used to detect whether any worker pods are alive when tasks are queued.
//
//encore:api private method=POST path=/internal/worker/heartbeat
func CronWorkerHeartbeat(ctx context.Context) error {
	core := skyforge.DefaultService()
	if core == nil || !core.TaskWorkerEnabled() {
		return nil
	}
	return core.UpsertTaskWorkerHeartbeat(ctx)
}

var _ = cron.NewJob("skyforge-worker-heartbeat", cron.JobConfig{
	Title:    "Task worker heartbeat",
	Endpoint: CronWorkerHeartbeat,
	Every:    1 * cron.Minute,
})
