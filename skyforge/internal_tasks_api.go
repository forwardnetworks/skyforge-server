package skyforge

import (
	"context"
	"crypto/subtle"
	"strings"

	"encore.dev/beta/errs"
)

type internalTaskReconcileParams struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

type internalTaskReconcileResponse struct {
	Ok bool `json:"ok"`
}

func validateInternalToken(cfg Config, token string) error {
	if strings.TrimSpace(cfg.InternalToken) == "" {
		return errs.B().Code(errs.NotFound).Msg("not found").Err()
	}
	token = strings.TrimSpace(token)
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(cfg.InternalToken)) != 1 {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return nil
}

// InternalReconcileQueuedTasks republishes queue events for queued tasks.
//
// This is intended for self-hosted deployments that run cron externally (e.g. Kubernetes CronJobs).
//
//encore:api public method=POST path=/api/internal/tasks/reconcile
func (s *Service) InternalReconcileQueuedTasks(ctx context.Context, params *internalTaskReconcileParams) (*internalTaskReconcileResponse, error) {
	if err := validateInternalToken(s.cfg, params.Token); err != nil {
		return nil, err
	}
	if err := ReconcileQueuedTasks(ctx); err != nil {
		return nil, err
	}
	return &internalTaskReconcileResponse{Ok: true}, nil
}

// InternalReconcileRunningTasks marks stuck "running" tasks as failed.
//
// This is intended for self-hosted deployments that run cron externally (e.g. Kubernetes CronJobs).
//
//encore:api public method=POST path=/api/internal/tasks/reconcile-running
func (s *Service) InternalReconcileRunningTasks(ctx context.Context, params *internalTaskReconcileParams) (*internalTaskReconcileResponse, error) {
	if err := validateInternalToken(s.cfg, params.Token); err != nil {
		return nil, err
	}
	if err := reconcileRunningTasks(ctx, s); err != nil {
		return nil, err
	}
	return &internalTaskReconcileResponse{Ok: true}, nil
}

