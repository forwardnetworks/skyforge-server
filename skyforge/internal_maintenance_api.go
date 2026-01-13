package skyforge

import (
	"context"

	"encore.app/internal/maintenance"
	"encore.dev/beta/errs"
)

type internalMaintenanceParams struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

type internalMaintenanceResponse struct {
	Ok bool `json:"ok"`
}

func (s *Service) enqueueMaintenance(ctx context.Context, kind string) error {
	if kind == "" {
		return nil
	}
	_, err := maintenance.Topic.Publish(ctx, &maintenance.MaintenanceEvent{Kind: kind})
	return err
}

// InternalWorkspaceSync enqueues a workspace sync job for worker execution.
//
// This is intended for self-hosted deployments that run cron externally (e.g. Kubernetes CronJobs).
//
//encore:api public method=POST path=/api/internal/workspaces/sync
func (s *Service) InternalWorkspaceSync(ctx context.Context, params *internalMaintenanceParams) (*internalMaintenanceResponse, error) {
	if err := validateInternalToken(s.cfg, params.Token); err != nil {
		return nil, err
	}
	if err := s.enqueueMaintenance(ctx, "workspace_sync"); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to enqueue workspace sync").Err()
	}
	return &internalMaintenanceResponse{Ok: true}, nil
}

// InternalCloudCredentialChecks enqueues a cloud credential check job for worker execution.
//
// This is intended for self-hosted deployments that run cron externally (e.g. Kubernetes CronJobs).
//
//encore:api public method=POST path=/api/internal/cloud/checks
func (s *Service) InternalCloudCredentialChecks(ctx context.Context, params *internalMaintenanceParams) (*internalMaintenanceResponse, error) {
	if err := validateInternalToken(s.cfg, params.Token); err != nil {
		return nil, err
	}
	if err := s.enqueueMaintenance(ctx, "cloud_credential_checks"); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to enqueue cloud credential checks").Err()
	}
	return &internalMaintenanceResponse{Ok: true}, nil
}

// InternalRefreshTaskQueueMetrics enqueues a task queue metrics refresh for worker execution.
//
// This is intended for self-hosted deployments that run cron externally (e.g. Kubernetes CronJobs).
//
//encore:api public method=POST path=/api/internal/tasks/metrics
func (s *Service) InternalRefreshTaskQueueMetrics(ctx context.Context, params *internalMaintenanceParams) (*internalMaintenanceResponse, error) {
	if err := validateInternalToken(s.cfg, params.Token); err != nil {
		return nil, err
	}
	if err := s.updateTaskQueueMetrics(ctx); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to refresh task queue metrics").Err()
	}
	return &internalMaintenanceResponse{Ok: true}, nil
}
