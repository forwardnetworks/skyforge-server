package skyforge

import (
	"context"
	"crypto/subtle"
	"strings"

	"encore.app/internal/skyforgeconfig"
	"encore.dev/beta/errs"
)

// InternalCronAuth guards cron bridge endpoints in self-hosted deployments.
// See worker/cron_bridge_api.go for the equivalent worker implementation.
type InternalCronAuth struct {
	Token string `header:"X-Skyforge-Internal-Token"`
}

func requireInternalCron(token string) error {
	want := strings.TrimSpace(getSecrets().InternalToken)
	if want == "" {
		return errs.B().Code(errs.NotFound).Msg("not found").Err()
	}
	token = strings.TrimSpace(token)
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return nil
}

// ReconcileCollectorBridge patches any existing in-cluster Forward collector Deployments
// to ensure they have the current Multus network attachments configured.
//
//encore:api public method=POST path=/internal/bridge/collector/reconcile
func ReconcileCollectorBridge(ctx context.Context, params *InternalCronAuth) error {
	if params == nil {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := requireInternalCron(params.Token); err != nil {
		return err
	}

	cfg := skyforgeconfig.LoadConfig(skyforgeEncoreCfg, getSecrets())
	_, err := reconcileCollectorMultusNetworks(ctx, cfg)
	return err
}
