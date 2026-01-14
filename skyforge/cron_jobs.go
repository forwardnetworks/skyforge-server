package skyforge

import (
	"context"

	"encore.app/internal/maintenance"
	"encore.dev/cron"
)

// Cron jobs
//
// These jobs are the preferred scheduling mechanism in Encore-managed environments.
// For self-hosted deployments that cannot (or do not want to) use Encore Cron, the
// Helm chart can instead enable Kubernetes CronJobs that hit the legacy internal
// trigger endpoints.

//encore:api private method=POST path=/internal/cron/workspaces/sync
func CronWorkspaceSync(ctx context.Context) error {
	_, err := maintenance.Topic.Publish(ctx, &maintenance.MaintenanceEvent{Kind: "workspace_sync"})
	return err
}

//encore:api private method=POST path=/internal/cron/cloud/checks
func CronCloudCredentialChecks(ctx context.Context) error {
	_, err := maintenance.Topic.Publish(ctx, &maintenance.MaintenanceEvent{Kind: "cloud_credential_checks"})
	return err
}

//encore:api private method=POST path=/internal/cron/tasks/metrics
func CronRefreshTaskQueueMetrics(ctx context.Context) error {
	if defaultService == nil {
		return nil
	}
	return defaultService.updateTaskQueueMetrics(ctx)
}

var (
	_ = cron.NewJob("skyforge-reconcile-queued", cron.JobConfig{
		Title:    "Reconcile queued tasks",
		Endpoint: ReconcileQueuedTasks,
		Every:    1 * cron.Minute,
	})
	_ = cron.NewJob("skyforge-reconcile-running", cron.JobConfig{
		Title:    "Reconcile running tasks",
		Endpoint: ReconcileRunningTasks,
		Every:    10 * cron.Minute,
	})
	_ = cron.NewJob("skyforge-workspace-sync", cron.JobConfig{
		Title:    "Sync workspaces",
		Endpoint: CronWorkspaceSync,
		Every:    5 * cron.Minute,
	})
	_ = cron.NewJob("skyforge-cloud-credential-checks", cron.JobConfig{
		Title:    "Cloud credential checks",
		Endpoint: CronCloudCredentialChecks,
		Every:    30 * cron.Minute,
	})
	_ = cron.NewJob("skyforge-task-queue-metrics", cron.JobConfig{
		Title:    "Refresh task queue metrics",
		Endpoint: CronRefreshTaskQueueMetrics,
		Every:    1 * cron.Minute,
	})
)

