package skyforge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/skyforgeconfig"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskstore"
	"encore.dev/cron"
	"encore.dev/rlog"
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

// Capacity rollups
//
// This job enqueues per-deployment rollup tasks for deployments that have Forward enabled.

//encore:api private method=POST path=/internal/cron/capacity/rollups
func CronEnqueueCapacityRollups(ctx context.Context) error {
	db, err := openSkyforgeDB(ctx)
	if err != nil || db == nil {
		return err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cfg := skyforgeconfig.LoadConfig(skyforgeEncoreCfg, getSecrets())
	_ = cfg // reserved for future knobs (rate limits, enable flags, etc.)

	type depRow struct {
		userContextID    string
		deploymentID     string
		createdBy        string
		forwardNetworkID string
	}
	rows, err := db.QueryContext(ctxReq, `SELECT workspace_id, id::text, created_by, COALESCE(config->>'forwardNetworkId','')
FROM sf_deployments
WHERE COALESCE(config->>'forwardEnabled','false') IN ('true','1','yes')
  AND COALESCE(config->>'forwardNetworkId','') <> ''
ORDER BY updated_at DESC
LIMIT 500`)
	if err != nil {
		return err
	}
	defer rows.Close()

	enqueued := 0
	for rows.Next() {
		var r depRow
		if scanErr := rows.Scan(&r.userContextID, &r.deploymentID, &r.createdBy, &r.forwardNetworkID); scanErr != nil {
			continue
		}
		r.userContextID = strings.TrimSpace(r.userContextID)
		r.deploymentID = strings.TrimSpace(r.deploymentID)
		r.createdBy = strings.TrimSpace(r.createdBy)
		if r.userContextID == "" || r.deploymentID == "" || r.createdBy == "" {
			continue
		}

		meta, _ := toJSONMap(map[string]any{"deploymentId": r.deploymentID, "cron": true})
		msg := fmt.Sprintf("Capacity rollup (cron)")
		task, err := createTaskAllowActive(ctx, db, r.userContextID, &r.deploymentID, "capacity-rollup", msg, r.createdBy, meta)
		if err != nil || task == nil || task.ID <= 0 {
			continue
		}

		key := fmt.Sprintf("%s:%s", r.userContextID, r.deploymentID)
		if _, err := taskQueueBackgroundTopic.Publish(ctx, &taskqueue.TaskEnqueuedEvent{TaskID: task.ID, Key: key}); err != nil {
			_ = taskstore.AppendTaskEvent(context.Background(), db, task.ID, "task.enqueue.publish_failed", map[string]any{
				"topic": "background",
				"err":   err.Error(),
			})
			rlog.Error("capacity rollup enqueue publish failed", "task_id", task.ID, "err", err)
			continue
		}
		enqueued++
	}
	// Also enqueue rollups for user-managed Forward networks (not tied to deployments).
	//
	// This allows capacity monitoring to be driven directly by Forward Network ID.
	type netRow struct {
		userContextID     string
		forwardNetworkID  string
		collectorConfigID string
		createdBy         string
	}
	nrows, err := db.QueryContext(ctxReq, `SELECT workspace_id, forward_network_id, COALESCE(collector_config_id,''), created_by
FROM sf_policy_report_forward_networks
ORDER BY updated_at DESC
LIMIT 500`)
	if err == nil {
		defer nrows.Close()
		for nrows.Next() {
			var r netRow
			if scanErr := nrows.Scan(&r.userContextID, &r.forwardNetworkID, &r.collectorConfigID, &r.createdBy); scanErr != nil {
				continue
			}
			r.userContextID = strings.TrimSpace(r.userContextID)
			r.forwardNetworkID = strings.TrimSpace(r.forwardNetworkID)
			r.collectorConfigID = strings.TrimSpace(r.collectorConfigID)
			r.createdBy = strings.TrimSpace(r.createdBy)
			if r.userContextID == "" || r.forwardNetworkID == "" || r.createdBy == "" {
				continue
			}

			metaAny := map[string]any{
				"forwardNetworkId":  r.forwardNetworkID,
				"collectorConfigId": r.collectorConfigID,
				"cron":              true,
			}
			meta, _ := toJSONMap(metaAny)
			msg := fmt.Sprintf("Capacity rollup (cron)")
			task, err := createTaskAllowActive(ctx, db, r.userContextID, nil, "capacity-rollup-forward-network", msg, r.createdBy, meta)
			if err != nil || task == nil || task.ID <= 0 {
				continue
			}

			key := fmt.Sprintf("%s:%s", r.userContextID, r.forwardNetworkID)
			if _, err := taskQueueBackgroundTopic.Publish(ctx, &taskqueue.TaskEnqueuedEvent{TaskID: task.ID, Key: key}); err != nil {
				_ = taskstore.AppendTaskEvent(context.Background(), db, task.ID, "task.enqueue.publish_failed", map[string]any{
					"topic": "background",
					"err":   err.Error(),
				})
				rlog.Error("capacity rollup enqueue publish failed", "task_id", task.ID, "err", err)
				continue
			}
			enqueued++
		}
	}
	rlog.Info("capacity rollups enqueued", "count", enqueued)
	return nil
}

var (
	_ = cron.NewJob("skyforge-capacity-rollups", cron.JobConfig{
		Title:    "Enqueue capacity rollups",
		Endpoint: CronEnqueueCapacityRollups,
		Every:    1 * cron.Hour,
	})
)

// Capacity cleanup
//
// Retain enough history for useful trending while keeping the database bounded.

//encore:api private method=POST path=/internal/cron/capacity/cleanup
func CronCleanupCapacity(ctx context.Context) error {
	db, err := openSkyforgeDB(ctx)
	if err != nil || db == nil {
		return err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Rollups: keep 90d of hourly rollups (covers 30d windows with margin).
	if _, err := db.ExecContext(ctxReq, `DELETE FROM sf_capacity_rollups WHERE period_end < now() - interval '90 days'`); err != nil {
		return err
	}

	// NQE cache: typically upserted to a single "latest" row (snapshot_id = ''), but keep a guardrail.
	if _, err := db.ExecContext(ctxReq, `DELETE FROM sf_capacity_nqe_cache WHERE created_at < now() - interval '30 days'`); err != nil {
		return err
	}
	return nil
}

var (
	_ = cron.NewJob("skyforge-capacity-cleanup", cron.JobConfig{
		Title:    "Cleanup capacity history",
		Endpoint: CronCleanupCapacity,
		Every:    24 * cron.Hour,
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
