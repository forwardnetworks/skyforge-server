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

// Governance usage snapshots
//
// This captures lightweight “ammo” metrics (cluster load + user activity counts)
// without requiring Prometheus/Grafana. Data is stored in sf_usage_snapshots and
// surfaced on the Admin → Governance page.

//encore:api private method=POST path=/internal/cron/governance/usage/snapshot
func CronSnapshotGovernanceUsage(ctx context.Context) error {
	db, err := openSkyforgeDB(ctx)
	if err != nil || db == nil {
		return err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return snapshotGovernanceUsage(ctxReq, db)
}

//encore:api private method=POST path=/internal/cron/governance/usage/cleanup
func CronCleanupGovernanceUsage(ctx context.Context) error {
	db, err := openSkyforgeDB(ctx)
	if err != nil || db == nil {
		return err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return cleanupGovernanceUsage(ctxReq, db)
}

var (
	_ = cron.NewJob("skyforge-governance-usage-snapshot", cron.JobConfig{
		Title:    "Snapshot governance usage",
		Endpoint: CronSnapshotGovernanceUsage,
		Every:    5 * cron.Minute,
	})

	_ = cron.NewJob("skyforge-governance-usage-cleanup", cron.JobConfig{
		Title:    "Cleanup governance usage history",
		Endpoint: CronCleanupGovernanceUsage,
		Every:    24 * cron.Hour,
	})
)
