package skyforge

import (
	"context"
	"time"

	"encore.app/internal/skyforgeconfig"
	"encore.dev/cron"
)

// Cron jobs
//
// These jobs are the preferred scheduling mechanism in Encore-managed environments.
// For self-hosted deployments that cannot (or do not want to) use Encore Cron, the
// Helm chart can instead enable Kubernetes CronJobs that hit the legacy internal
// trigger endpoints.

//encore:api private method=POST path=/internal/cron/tasks/metrics
func CronRefreshTaskQueueMetrics(ctx context.Context) error {
	db, err := openSkyforgeDB(ctx)
	if err != nil || db == nil {
		return err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cfg := skyforgeconfig.LoadConfig(skyforgeEncoreCfg, getSecrets())
	return updateTaskQueueMetrics(ctxReq, cfg, db)
}

var (
	_ = cron.NewJob("skyforge-task-queue-metrics", cron.JobConfig{
		Title:    "Refresh task queue metrics",
		Endpoint: CronRefreshTaskQueueMetrics,
		Every:    1 * cron.Minute,
	})
)
