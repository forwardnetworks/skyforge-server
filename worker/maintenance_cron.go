package worker

import (
	"context"

	"encore.app/internal/maintenance"
	"encore.dev/cron"
)

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

var (
	_ = cron.NewJob("worker-workspace-sync", cron.JobConfig{
		Title:    "Sync workspaces",
		Endpoint: CronWorkspaceSync,
		Every:    5 * cron.Minute,
	})
	_ = cron.NewJob("worker-cloud-credential-checks", cron.JobConfig{
		Title:    "Cloud credential checks",
		Endpoint: CronCloudCredentialChecks,
		Every:    30 * cron.Minute,
	})
)
