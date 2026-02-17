package taskengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type capacityRollupForwardNetworkTaskSpec struct {
	ForwardNetworkID  string `json:"forwardNetworkId"`
	CollectorConfigID string `json:"collectorConfigId,omitempty"`
}

func (e *Engine) dispatchCapacityRollupForwardNetworkTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if e == nil || task == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}

	var specIn capacityRollupForwardNetworkTaskSpec
	_ = decodeTaskSpec(task, &specIn)

	ws, err := e.loadUserContextByKey(ctx, task.WorkspaceID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &userContext{
		userContext: *ws,
		claims: SessionClaims{
			Username: username,
		},
	}

	forwardNetworkID := strings.TrimSpace(specIn.ForwardNetworkID)
	if forwardNetworkID == "" {
		return fmt.Errorf("forwardNetworkId is required")
	}
	collectorConfigID := strings.TrimSpace(specIn.CollectorConfigID)

	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "capacity.rollup.forward_network", func() error {
		return e.runCapacityRollupForwardNetwork(ctx, pc, forwardNetworkID, collectorConfigID, task.ID, log)
	})
}

func (e *Engine) runCapacityRollupForwardNetwork(ctx context.Context, pc *userContext, forwardNetworkID string, collectorConfigID string, taskID int, log Logger) error {
	if e == nil || e.db == nil {
		return fmt.Errorf("engine unavailable")
	}
	if pc == nil {
		return fmt.Errorf("user context unavailable")
	}
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if forwardNetworkID == "" {
		return fmt.Errorf("forward network id is required")
	}

	fwdCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil {
		return err
	}
	if fwdCfg == nil {
		return fmt.Errorf("Forward credentials missing for user")
	}
	client, err := newForwardClient(forwardCredentials{BaseURL: fwdCfg.BaseURL, Username: fwdCfg.Username, Password: fwdCfg.Password, SkipTLSVerify: fwdCfg.SkipTLSVerify})
	if err != nil {
		return err
	}

	periodEnd := time.Now().UTC().Truncate(time.Hour)
	if log != nil {
		log.Infof("Capacity rollup start (forwardNetworkId=%s asOf=%s)", forwardNetworkID, periodEnd.Format(time.RFC3339))
	}
	windows := []windowSpec{
		{Label: "24h", Days: 1},
		{Label: "7d", Days: 7},
		{Label: "30d", Days: 30},
	}

	// Refresh NQE cache and load enrichment maps for rollup details.
	inv, invErr := e.refreshCapacityInventoryCache(ctx, e.db, client, pc.userContext.ID, nil, forwardNetworkID, log)
	if invErr != nil && log != nil {
		log.Errorf("capacity inventory refresh failed: %v", invErr)
	}

	for _, w := range windows {
		threshold := 0.85
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "UTILIZATION", "util_ingress", "INGRESS", &threshold, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "UTILIZATION", "INGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "UTILIZATION", "util_egress", "EGRESS", &threshold, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "UTILIZATION", "EGRESS", err)
		}

		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "ERROR", "if_error_ingress", "INGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "ERROR", "INGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "ERROR", "if_error_egress", "EGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "ERROR", "EGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "PACKET_LOSS", "if_packet_loss_ingress", "INGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "PACKET_LOSS", "INGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "PACKET_LOSS", "if_packet_loss_egress", "EGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "PACKET_LOSS", "EGRESS", err)
		}

		if err := e.rollupDeviceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "CPU", inv, taskID, log); err != nil {
			log.Errorf("device rollup failed (window=%s type=%s): %v", w.Label, "CPU", err)
		}
		if err := e.rollupDeviceMetric(ctx, client, pc.userContext.ID, nil, forwardNetworkID, periodEnd, w, "MEMORY", inv, taskID, log); err != nil {
			log.Errorf("device rollup failed (window=%s type=%s): %v", w.Label, "MEMORY", err)
		}
	}

	_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "capacity.rollup.completed", map[string]any{
		"forwardNetworkId": forwardNetworkID,
		"asOf":             periodEnd.Format(time.RFC3339),
	})
	return nil
}
