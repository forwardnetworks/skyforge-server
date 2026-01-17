package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type InternalRunMaintenanceParams struct {
	Kind string `json:"kind"`
}

// InternalRunMaintenance executes a maintenance job by kind.
//
// This is intended for in-cluster use by the `worker` service.
//
//encore:api private method=POST path=/internal/maintenance/run
func (s *Service) InternalRunMaintenance(ctx context.Context, params *InternalRunMaintenanceParams) error {
	if s == nil || s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	if params == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	kind := strings.TrimSpace(params.Kind)
	switch kind {
	case "workspace_sync":
		return s.runWithAdvisoryLock(ctx, 74004, func(ctx context.Context) error {
			runWorkspaceSync(s.cfg, s.workspaceStore, s.db)
			return nil
		})
	case "cloud_credential_checks":
		return s.runWithAdvisoryLock(ctx, 74005, func(ctx context.Context) error {
			runCloudCredentialChecks(s.cfg, s.workspaceStore, s.awsStore, s.db)
			return nil
		})
	default:
		rlog.Info("maintenance: ignoring unknown job kind", "kind", kind)
		return nil
	}
}
