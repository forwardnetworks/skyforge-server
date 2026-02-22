package worker

import (
	"context"
	"crypto/subtle"
	"strings"

	"encore.dev/beta/errs"
)

// InternalCronAuth guards cron bridge endpoints in self-hosted deployments.
//
// Encore's managed cron scheduler is not available in our k3s setup, so we expose
// a token-guarded HTTP bridge that Kubernetes CronJobs can call.
type InternalCronAuth struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

func requireInternalCron(token string) error {
	want := strings.TrimSpace(secrets.SKYFORGE_INTERNAL_TOKEN)
	if want == "" {
		return errs.B().Code(errs.NotFound).Msg("not found").Err()
	}
	token = strings.TrimSpace(token)
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return nil
}

// CronWorkerHeartbeatBridge triggers the worker heartbeat task.
//
//encore:api public method=POST path=/internal/bridge/worker/heartbeat
func CronWorkerHeartbeatBridge(ctx context.Context, params *InternalCronAuth) error {
	if params == nil {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := requireInternalCron(params.Token); err != nil {
		return err
	}
	return CronWorkerHeartbeat(ctx)
}

// CronReconcileQueuedTasksBridge triggers reconciliation for queued tasks.
//
//encore:api public method=POST path=/internal/bridge/worker/tasks/reconcile
func CronReconcileQueuedTasksBridge(ctx context.Context, params *InternalCronAuth) error {
	if params == nil {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := requireInternalCron(params.Token); err != nil {
		return err
	}
	return CronReconcileQueuedTasks(ctx)
}

// CronReconcileRunningTasksBridge triggers reconciliation for running tasks.
//
//encore:api public method=POST path=/internal/bridge/worker/tasks/reconcile-running
func CronReconcileRunningTasksBridge(ctx context.Context, params *InternalCronAuth) error {
	if params == nil {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := requireInternalCron(params.Token); err != nil {
		return err
	}
	return CronReconcileRunningTasks(ctx)
}

// CronUserSyncBridge triggers user sync maintenance.
//
//encore:api public method=POST path=/internal/bridge/users/sync
func CronUserSyncBridge(ctx context.Context, params *InternalCronAuth) error {
	if params == nil {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := requireInternalCron(params.Token); err != nil {
		return err
	}
	return CronUserSync(ctx)
}

// CronCloudCredentialChecksBridge triggers cloud credential checks maintenance.
//
//encore:api public method=POST path=/internal/bridge/cloud/checks
func CronCloudCredentialChecksBridge(ctx context.Context, params *InternalCronAuth) error {
	if params == nil {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := requireInternalCron(params.Token); err != nil {
		return err
	}
	return CronCloudCredentialChecks(ctx)
}
