package skyforge

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"encore.app/internal/governanceutil"
	"encore.dev/rlog"
)

const (
	governanceUsageProvider   = "skyforge"
	governanceUsageRetention  = 14 * 24 * time.Hour
	governanceNodeMetricStale = 2 * time.Minute
)

type nodeMetricSnapshotRow struct {
	Node      string
	Metric    string
	UpdatedAt time.Time
	RawJSON   string
}

func snapshotGovernanceUsage(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return sql.ErrConnDone
	}

	// Cluster load (p95 CPU/mem/disk across nodes).
	if err := snapshotClusterLoadUsage(ctx, db); err != nil {
		rlog.Warn("governance usage: cluster load snapshot failed", "err", err)
	}

	// User activity (deployments/runs/collectors).
	if err := snapshotUserActivityUsage(ctx, db); err != nil {
		rlog.Warn("governance usage: user activity snapshot failed", "err", err)
	}

	// Kubernetes inventory (pods/namespaces).
	if err := snapshotK8sInventoryUsage(ctx, db); err != nil {
		rlog.Warn("governance usage: k8s inventory snapshot failed", "err", err)
	}

	return nil
}

func cleanupGovernanceUsage(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return sql.ErrConnDone
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctxReq, `
DELETE FROM sf_usage_snapshots
WHERE collected_at < now() - ($1::interval)
`, governanceutil.IntervalString(governanceUsageRetention))
	return err
}

func snapshotClusterLoadUsage(ctx context.Context, db *sql.DB) error {
	rows, err := listRecentNodeMetricSnapshotsRaw(ctx, db, governanceNodeMetricStale, 5000)
	if err != nil {
		return err
	}
	latest := map[string]map[string]nodeMetricSnapshotRow{} // metric -> node -> row
	for _, row := range rows {
		node := strings.TrimSpace(row.Node)
		metric := strings.TrimSpace(row.Metric)
		if node == "" || metric == "" {
			continue
		}
		if latest[metric] == nil {
			latest[metric] = map[string]nodeMetricSnapshotRow{}
		}
		prev, ok := latest[metric][node]
		if !ok || row.UpdatedAt.After(prev.UpdatedAt) {
			latest[metric][node] = row
		}
	}

	cpuVals := make([]float64, 0, 64)
	memVals := make([]float64, 0, 64)
	diskVals := make([]float64, 0, 64)

	for _, row := range latest["cpu"] {
		if v := extractFloatField(row.RawJSON, "usage_active"); v != nil {
			cpuVals = append(cpuVals, *v)
		}
	}
	for _, row := range latest["mem"] {
		if v := extractFloatField(row.RawJSON, "used_percent"); v != nil {
			memVals = append(memVals, *v)
		}
	}
	for _, row := range latest["disk"] {
		if v := extractFloatField(row.RawJSON, "used_percent"); v != nil {
			diskVals = append(diskVals, *v)
		}
	}

	if len(cpuVals) == 0 && len(memVals) == 0 && len(diskVals) == 0 {
		return nil
	}

	if len(cpuVals) > 0 {
		_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
			Provider:    governanceUsageProvider,
			ScopeType:   "cluster",
			Metric:      "node.cpu_active.p95",
			Value:       governanceutil.Percentile(cpuVals, 0.95),
			Unit:        "percent",
			WorkspaceID: "",
		})
	}
	if len(memVals) > 0 {
		_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
			Provider:    governanceUsageProvider,
			ScopeType:   "cluster",
			Metric:      "node.mem_used.p95",
			Value:       governanceutil.Percentile(memVals, 0.95),
			Unit:        "percent",
			WorkspaceID: "",
		})
	}
	if len(diskVals) > 0 {
		_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
			Provider:    governanceUsageProvider,
			ScopeType:   "cluster",
			Metric:      "node.disk_used.p95",
			Value:       governanceutil.Percentile(diskVals, 0.95),
			Unit:        "percent",
			WorkspaceID: "",
		})
	}

	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:    governanceUsageProvider,
		ScopeType:   "cluster",
		Metric:      "node.count",
		Value:       float64(len(uniqueKeys(latest))),
		Unit:        "count",
		WorkspaceID: "",
	})

	return nil
}

func uniqueKeys(m map[string]map[string]nodeMetricSnapshotRow) map[string]struct{} {
	out := map[string]struct{}{}
	for _, byNode := range m {
		for node := range byNode {
			out[node] = struct{}{}
		}
	}
	return out
}

func listRecentNodeMetricSnapshotsRaw(ctx context.Context, db *sql.DB, since time.Duration, limit int) ([]nodeMetricSnapshotRow, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	cutoff := time.Now().UTC().Add(-since)
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
SELECT node, metric_name, updated_at, metric_json::text
FROM sf_node_metric_snapshots
WHERE updated_at >= $1
ORDER BY updated_at DESC
LIMIT $2
`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]nodeMetricSnapshotRow, 0, 256)
	for rows.Next() {
		var r nodeMetricSnapshotRow
		if err := rows.Scan(&r.Node, &r.Metric, &r.UpdatedAt, &r.RawJSON); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func snapshotUserActivityUsage(ctx context.Context, db *sql.DB) error {
	// Per-user totals.
	deployTotal, err := countDeploymentsByUser(ctx, db)
	if err != nil {
		return err
	}
	collectorTotal, err := countCollectorsByUser(ctx, db)
	if err != nil {
		return err
	}
	runningTasksByUser, err := countRunningTasksByUser(ctx, db)
	if err != nil {
		return err
	}
	activeDeploymentsByUser, err := countActiveDeploymentsByUser(ctx, db)
	if err != nil {
		return err
	}
	activeUsers24h, err := countActiveUsersLast24h(ctx, db)
	if err != nil {
		return err
	}
	queuedTasks, runningTasks, oldestQueuedAgeSeconds, err := taskQueueSummary(ctx, db)
	if err != nil {
		return err
	}

	allUsers := map[string]struct{}{}
	for u := range deployTotal {
		allUsers[u] = struct{}{}
	}
	for u := range collectorTotal {
		allUsers[u] = struct{}{}
	}
	for u := range runningTasksByUser {
		allUsers[u] = struct{}{}
	}
	for u := range activeDeploymentsByUser {
		allUsers[u] = struct{}{}
	}

	// Cluster totals.
	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:  governanceUsageProvider,
		ScopeType: "cluster",
		Metric:    "users.active_24h",
		Value:     float64(activeUsers24h),
		Unit:      "count",
	})

	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:  governanceUsageProvider,
		ScopeType: "cluster",
		Metric:    "deployments.total",
		Value:     float64(sumIntMap(deployTotal)),
		Unit:      "count",
	})

	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:  governanceUsageProvider,
		ScopeType: "cluster",
		Metric:    "deployments.active",
		Value:     float64(sumIntMap(activeDeploymentsByUser)),
		Unit:      "count",
	})

	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:  governanceUsageProvider,
		ScopeType: "cluster",
		Metric:    "collectors.total",
		Value:     float64(sumIntMap(collectorTotal)),
		Unit:      "count",
	})

	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:  governanceUsageProvider,
		ScopeType: "cluster",
		Metric:    "tasks.running",
		Value:     float64(runningTasks),
		Unit:      "count",
	})

	_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
		Provider:  governanceUsageProvider,
		ScopeType: "cluster",
		Metric:    "tasks.queued",
		Value:     float64(queuedTasks),
		Unit:      "count",
	})

	if oldestQueuedAgeSeconds > 0 {
		_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
			Provider:  governanceUsageProvider,
			ScopeType: "cluster",
			Metric:    "tasks.oldest_queued_age_seconds",
			Value:     float64(oldestQueuedAgeSeconds),
			Unit:      "seconds",
		})
	}

	// Per-user snapshots.
	for user := range allUsers {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}
		if v := deployTotal[user]; v > 0 {
			_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
				Provider:  governanceUsageProvider,
				ScopeType: "user",
				ScopeID:   user,
				Metric:    "deployments.total",
				Value:     float64(v),
				Unit:      "count",
			})
		}
		if v := activeDeploymentsByUser[user]; v > 0 {
			_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
				Provider:  governanceUsageProvider,
				ScopeType: "user",
				ScopeID:   user,
				Metric:    "deployments.active",
				Value:     float64(v),
				Unit:      "count",
			})
		}
		if v := collectorTotal[user]; v > 0 {
			_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
				Provider:  governanceUsageProvider,
				ScopeType: "user",
				ScopeID:   user,
				Metric:    "collectors.total",
				Value:     float64(v),
				Unit:      "count",
			})
		}
		if v := runningTasksByUser[user]; v > 0 {
			_, _ = insertGovernanceUsage(ctx, db, GovernanceUsageInput{
				Provider:  governanceUsageProvider,
				ScopeType: "user",
				ScopeID:   user,
				Metric:    "tasks.running",
				Value:     float64(v),
				Unit:      "count",
			})
		}
	}
	return nil
}

type kubeInventoryCounts struct {
	governanceutil.InventoryCounts
}

func snapshotK8sInventoryUsage(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return sql.ErrConnDone
	}

	client, err := kubeHTTPClient()
	if err != nil {
		// Likely not running in-cluster; treat as best-effort.
		return nil
	}

	ctxReq, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	counts, err := governanceutil.CollectInventoryCountsWithRequest(
		ctxReq,
		client,
		kubeNamespace(),
		governanceutil.KubeDefaultAPIBaseURL,
		func(ctx context.Context, method, u string) (*http.Request, error) {
			return kubeRequest(ctx, method, u, nil)
		},
	)
	if err != nil {
		return err
	}

	metrics := []struct {
		metric string
		value  int
		unit   string
	}{
		{"k8s.namespaces.total", counts.NamespacesTotal, "count"},
		{"k8s.namespaces.ws", counts.NamespacesWS, "count"},
		{"k8s.pods.total", counts.PodsTotal, "count"},
		{"k8s.pods.pending", counts.PodsPending, "count"},
		{"k8s.pods.ws.total", counts.PodsWSTotal, "count"},
		{"k8s.pods.ws.pending", counts.PodsWSPending, "count"},
		{"k8s.pods.platform.total", counts.PodsPlatformTotal, "count"},
		{"k8s.pods.platform.pending", counts.PodsPlatformPending, "count"},
	}

	for _, m := range metrics {
		_, _ = insertGovernanceUsage(ctxReq, db, GovernanceUsageInput{
			Provider:  governanceUsageProvider,
			ScopeType: "cluster",
			Metric:    m.metric,
			Value:     float64(m.value),
			Unit:      m.unit,
		})
	}

	return nil
}

func sumIntMap(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

func countDeploymentsByUser(ctx context.Context, db *sql.DB) (map[string]int, error) {
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
SELECT created_by, COUNT(*)::int
FROM sf_deployments
GROUP BY created_by
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var user string
		var c int
		if err := rows.Scan(&user, &c); err != nil {
			return nil, err
		}
		user = strings.TrimSpace(user)
		if user != "" {
			out[user] = c
		}
	}
	return out, rows.Err()
}

func countCollectorsByUser(ctx context.Context, db *sql.DB) (map[string]int, error) {
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
SELECT username, COUNT(*)::int
FROM sf_user_forward_collectors
GROUP BY username
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var user string
		var c int
		if err := rows.Scan(&user, &c); err != nil {
			return nil, err
		}
		user = strings.TrimSpace(user)
		if user != "" {
			out[user] = c
		}
	}
	return out, rows.Err()
}

func countRunningTasksByUser(ctx context.Context, db *sql.DB) (map[string]int, error) {
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
SELECT created_by, COUNT(*)::int
FROM sf_tasks
WHERE status = 'running'
GROUP BY created_by
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var user string
		var c int
		if err := rows.Scan(&user, &c); err != nil {
			return nil, err
		}
		user = strings.TrimSpace(user)
		if user != "" {
			out[user] = c
		}
	}
	return out, rows.Err()
}

func countActiveDeploymentsByUser(ctx context.Context, db *sql.DB) (map[string]int, error) {
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
SELECT created_by, COUNT(DISTINCT deployment_id)::int
FROM sf_tasks
WHERE status = 'running' AND deployment_id IS NOT NULL
GROUP BY created_by
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var user string
		var c int
		if err := rows.Scan(&user, &c); err != nil {
			return nil, err
		}
		user = strings.TrimSpace(user)
		if user != "" {
			out[user] = c
		}
	}
	return out, rows.Err()
}

func countActiveUsersLast24h(ctx context.Context, db *sql.DB) (int, error) {
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	row := db.QueryRowContext(ctxReq, `
WITH recent AS (
  SELECT created_by AS u FROM sf_tasks WHERE created_at >= now() - interval '24 hours'
  UNION
  SELECT created_by AS u FROM sf_deployments WHERE created_at >= now() - interval '24 hours'
  UNION
  SELECT username AS u FROM sf_user_forward_collectors WHERE created_at >= now() - interval '24 hours'
)
SELECT COUNT(DISTINCT u)::int FROM recent
`)
	var c int
	if err := row.Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}
