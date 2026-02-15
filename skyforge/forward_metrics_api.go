package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type ForwardMetricsHistoryQuery struct {
	Limit int `query:"limit" encore:"optional"`
}

type ForwardMetricsSnapshot struct {
	CollectedAt                   string  `json:"collectedAt"`
	SnapshotID                    string  `json:"snapshotId,omitempty"`
	NumSuccessfulDevices          *int    `json:"numSuccessfulDevices,omitempty"`
	NumCollectionFailureDevices   *int    `json:"numCollectionFailureDevices,omitempty"`
	NumProcessingFailureDevices   *int    `json:"numProcessingFailureDevices,omitempty"`
	NumSuccessfulEndpoints        *int    `json:"numSuccessfulEndpoints,omitempty"`
	NumCollectionFailureEndpoints *int    `json:"numCollectionFailureEndpoints,omitempty"`
	NumProcessingFailureEndpoints *int    `json:"numProcessingFailureEndpoints,omitempty"`
	CollectionDurationMs          *int64  `json:"collectionDurationMs,omitempty"`
	ProcessingDurationMs          *int64  `json:"processingDurationMs,omitempty"`
	Source                        string  `json:"source,omitempty"`
	Raw                           JSONMap `json:"raw,omitempty"`
}

type ForwardMetricsSummaryResponse struct {
	WorkspaceID      string                  `json:"workspaceId"`
	NetworkRef       string                  `json:"networkRef"`
	ForwardNetworkID string                  `json:"forwardNetworkId"`
	Snapshot         *ForwardMetricsSnapshot `json:"snapshot,omitempty"`
	Stale            bool                    `json:"stale"`
}

type ForwardMetricsHistoryResponse struct {
	WorkspaceID      string                   `json:"workspaceId"`
	NetworkRef       string                   `json:"networkRef"`
	ForwardNetworkID string                   `json:"forwardNetworkId"`
	Items            []ForwardMetricsSnapshot `json:"items"`
}

type AdminForwardMetricsSyncResponse struct {
	OK bool   `json:"ok"`
	At string `json:"at,omitempty"`
}

type AdminForwardMetricsPollStateResponse struct {
	Enabled           bool   `json:"enabled"`
	IntervalMinutes   int    `json:"intervalMinutes"`
	LatestCollectedAt string `json:"latestCollectedAt,omitempty"`
}

func forwardMetricsSnapshotFromRow(row *forwardMetricsSnapshotRow) *ForwardMetricsSnapshot {
	if row == nil {
		return nil
	}
	raw, _ := toJSONMap(parseForwardMetricsJSON(row.RawMetricsJSON))
	return &ForwardMetricsSnapshot{
		CollectedAt:                   row.CollectedAt.UTC().Format(time.RFC3339),
		SnapshotID:                    strings.TrimSpace(row.SnapshotID),
		NumSuccessfulDevices:          maybeIntPtr(row.NumSuccessfulDevices),
		NumCollectionFailureDevices:   maybeIntPtr(row.NumCollectionFailureDevices),
		NumProcessingFailureDevices:   maybeIntPtr(row.NumProcessingFailureDevices),
		NumSuccessfulEndpoints:        maybeIntPtr(row.NumSuccessfulEndpoints),
		NumCollectionFailureEndpoints: maybeIntPtr(row.NumCollectionFailureEndpoints),
		NumProcessingFailureEndpoints: maybeIntPtr(row.NumProcessingFailureEndpoints),
		CollectionDurationMs:          maybeInt64Ptr(row.CollectionDurationMs),
		ProcessingDurationMs:          maybeInt64Ptr(row.ProcessingDurationMs),
		Source:                        strings.TrimSpace(row.Source),
		Raw:                           raw,
	}
}

func forwardMetricsStaleAt(t time.Time) bool {
	if t.IsZero() {
		return true
	}
	return time.Since(t) > 20*time.Minute
}

func collectForwardMetricsSnapshot(ctx context.Context, client *forwardClient) (string, forwardSnapshotMetrics, []byte, error) {
	if client == nil {
		return "", forwardSnapshotMetrics{}, nil, fmt.Errorf("forward client unavailable")
	}
	latestBody, err := forwardGETJSON(ctx, client, "/api/snapshots/latestProcessed", nil)
	if err != nil {
		return "", forwardSnapshotMetrics{}, nil, err
	}
	snapshotID := strings.TrimSpace(parseForwardSnapshotIDFromLatestProcessed(latestBody))
	if snapshotID == "" {
		return "", forwardSnapshotMetrics{}, nil, fmt.Errorf("forward snapshot id unavailable")
	}
	metricsPath := fmt.Sprintf("/api/snapshots/%s/metrics", url.PathEscape(snapshotID))
	metricsBody, err := forwardGETJSON(ctx, client, metricsPath, nil)
	if err != nil {
		return snapshotID, forwardSnapshotMetrics{}, nil, err
	}
	var met forwardSnapshotMetrics
	if err := parseJSONBytesInto(metricsBody, &met); err != nil {
		return snapshotID, forwardSnapshotMetrics{}, nil, err
	}
	return snapshotID, met, metricsBody, nil
}

func persistForwardMetricsSnapshot(ctx context.Context, db *sql.DB, workspaceID, ownerUsername, networkRef, forwardNetworkID, snapshotID string, met forwardSnapshotMetrics, raw []byte, source string) error {
	if db == nil {
		return sql.ErrConnDone
	}
	row := forwardMetricsSnapshotRow{
		WorkspaceID:                   strings.TrimSpace(workspaceID),
		OwnerUsername:                 strings.ToLower(strings.TrimSpace(ownerUsername)),
		NetworkRef:                    strings.TrimSpace(networkRef),
		ForwardNetworkID:              strings.TrimSpace(forwardNetworkID),
		SnapshotID:                    strings.TrimSpace(snapshotID),
		CollectedAt:                   time.Now().UTC(),
		NumSuccessfulDevices:          met.NumSuccessfulDevices,
		NumCollectionFailureDevices:   met.NumCollectionFailureDevices,
		NumProcessingFailureDevices:   met.NumProcessingFailureDevices,
		NumSuccessfulEndpoints:        met.NumSuccessfulEndpoints,
		NumCollectionFailureEndpoints: met.NumCollectionFailureEndpoints,
		NumProcessingFailureEndpoints: met.NumProcessingFailureEndpoints,
		Source:                        strings.TrimSpace(source),
		RawMetricsJSON:                strings.TrimSpace(string(raw)),
	}
	if met.CollectionDuration > 0 {
		v := met.CollectionDuration
		row.CollectionDurationMs = &v
	}
	if met.ProcessingDuration > 0 {
		v := met.ProcessingDuration
		row.ProcessingDurationMs = &v
	}
	return insertForwardMetricsSnapshot(ctx, db, row)
}

func forwardMetricsSyncOne(ctx context.Context, db *sql.DB, client *forwardClient, workspaceID, ownerUsername, networkRef, forwardNetworkID, source string) (*forwardMetricsSnapshotRow, error) {
	snapshotID, met, raw, err := collectForwardMetricsSnapshot(ctx, client)
	if err != nil {
		return nil, err
	}
	if err := persistForwardMetricsSnapshot(ctx, db, workspaceID, ownerUsername, networkRef, forwardNetworkID, snapshotID, met, raw, source); err != nil {
		return nil, err
	}
	forwardMetricsSnapshotsStored.Add(1)
	row, _ := latestForwardMetricsSnapshot(ctx, db, workspaceID, ownerUsername, networkRef, forwardNetworkID)
	if row != nil {
		return row, nil
	}
	return &forwardMetricsSnapshotRow{
		WorkspaceID:      workspaceID,
		OwnerUsername:    ownerUsername,
		NetworkRef:       networkRef,
		ForwardNetworkID: forwardNetworkID,
		SnapshotID:       snapshotID,
		CollectedAt:      time.Now().UTC(),
		Source:           source,
		RawMetricsJSON:   string(raw),
	}, nil
}

func forwardMetricsPollingEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(getEnvDefault("SKYFORGE_FORWARD_METRICS_POLL_ENABLED", "true")))
	switch raw {
	case "", "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func forwardMetricsPollingIntervalMinutes() int {
	v, err := strconv.Atoi(strings.TrimSpace(getEnvDefault("SKYFORGE_FORWARD_METRICS_POLL_MINUTES", "5")))
	if err != nil || v <= 0 {
		return 5
	}
	if v > 120 {
		return 120
	}
	return v
}

func getEnvDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return strings.TrimSpace(fallback)
}

func syncForwardMetricsCron(ctx context.Context, db *sql.DB, cfg Config) error {
	if db == nil {
		return sql.ErrConnDone
	}
	if !cfg.Features.ForwardEnabled || !forwardMetricsPollingEnabled() {
		return nil
	}

	type netRow struct {
		WorkspaceID       string
		OwnerUsername     string
		CreatedBy         string
		NetworkRef        string
		ForwardNetworkID  string
		CollectorConfigID string
	}

	ctxReq, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
SELECT COALESCE(workspace_id,''),
       COALESCE(owner_username,''),
       COALESCE(created_by,''),
       id::text,
       COALESCE(forward_network_id,''),
       COALESCE(collector_config_id,'')
  FROM sf_policy_report_forward_networks
 ORDER BY updated_at DESC
 LIMIT 500
`)
	if err != nil {
		if isMissingDBRelation(err) {
			return nil
		}
		return err
	}
	defer rows.Close()

	networks := make([]netRow, 0, 128)
	for rows.Next() {
		var r netRow
		if err := rows.Scan(&r.WorkspaceID, &r.OwnerUsername, &r.CreatedBy, &r.NetworkRef, &r.ForwardNetworkID, &r.CollectorConfigID); err != nil {
			continue
		}
		r.WorkspaceID = strings.TrimSpace(r.WorkspaceID)
		r.OwnerUsername = strings.ToLower(strings.TrimSpace(r.OwnerUsername))
		r.CreatedBy = strings.ToLower(strings.TrimSpace(r.CreatedBy))
		r.NetworkRef = strings.TrimSpace(r.NetworkRef)
		r.ForwardNetworkID = strings.TrimSpace(r.ForwardNetworkID)
		r.CollectorConfigID = strings.TrimSpace(r.CollectorConfigID)
		if r.ForwardNetworkID == "" {
			continue
		}
		if r.OwnerUsername == "" {
			r.OwnerUsername = r.CreatedBy
		}
		if r.OwnerUsername == "" && r.WorkspaceID == "" {
			continue
		}
		networks = append(networks, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(networks) == 0 {
		return nil
	}

	forwardMetricsSyncRunsTotal.With(forwardMetricsSyncSourceLabels{Source: "cron"}).Add(1)
	forwardMetricsLastRunUnix.With(forwardMetricsSyncSourceLabels{Source: "cron"}).Set(float64(time.Now().Unix()))

	success := 0
	failed := 0
	for _, net := range networks {
		creds, err := resolveForwardCredentialsFor(ctx, db, cfg.SessionSecret, net.WorkspaceID, net.OwnerUsername, net.ForwardNetworkID, forwardCredResolveOpts{CollectorConfigID: net.CollectorConfigID})
		if err != nil || creds == nil {
			failed++
			continue
		}
		client, err := newForwardClient(*creds)
		if err != nil {
			failed++
			continue
		}
		netCtx, cancelNet := context.WithTimeout(ctx, 30*time.Second)
		_, err = forwardMetricsSyncOne(netCtx, db, client, net.WorkspaceID, net.OwnerUsername, net.NetworkRef, net.ForwardNetworkID, "cron")
		cancelNet()
		if err != nil {
			failed++
			rlog.Warn("forward metrics sync failed", "network_ref", net.NetworkRef, "forward_network_id", net.ForwardNetworkID, "err", err)
			continue
		}
		success++
	}
	if failed > 0 {
		forwardMetricsSyncFailuresTotal.With(forwardMetricsSyncSourceLabels{Source: "cron"}).Add(uint64(failed))
	}
	rlog.Info("forward metrics cron sync complete", "success", success, "failed", failed)
	return nil
}

// GetWorkspaceForwardNetworkMetricsSummary returns the latest stored Forward metrics sample.
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/metrics/summary
func (s *Service) GetWorkspaceForwardNetworkMetricsSummary(ctx context.Context, id, networkRef string) (*ForwardMetricsSummaryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	row, err := latestForwardMetricsSnapshot(ctxReq, s.db, pc.workspace.ID, pc.claims.Username, net.ID, net.ForwardNetworkID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &ForwardMetricsSummaryResponse{WorkspaceID: pc.workspace.ID, NetworkRef: net.ID, ForwardNetworkID: net.ForwardNetworkID, Stale: true}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load forward metrics").Err()
	}
	stale := true
	if row != nil {
		stale = forwardMetricsStaleAt(row.CollectedAt)
	}
	return &ForwardMetricsSummaryResponse{
		WorkspaceID:      pc.workspace.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Snapshot:         forwardMetricsSnapshotFromRow(row),
		Stale:            stale,
	}, nil
}

// GetWorkspaceForwardNetworkMetricsHistory returns recent stored Forward metrics samples.
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/metrics/history
func (s *Service) GetWorkspaceForwardNetworkMetricsHistory(ctx context.Context, id, networkRef string, q *ForwardMetricsHistoryQuery) (*ForwardMetricsHistoryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	limit := 100
	if q != nil && q.Limit > 0 {
		limit = q.Limit
	}
	if limit > 500 {
		limit = 500
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := listForwardMetricsSnapshots(ctxReq, s.db, pc.workspace.ID, pc.claims.Username, net.ID, net.ForwardNetworkID, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return &ForwardMetricsHistoryResponse{WorkspaceID: pc.workspace.ID, NetworkRef: net.ID, ForwardNetworkID: net.ForwardNetworkID, Items: []ForwardMetricsSnapshot{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load forward metrics history").Err()
	}
	items := make([]ForwardMetricsSnapshot, 0, len(rows))
	for i := range rows {
		if snap := forwardMetricsSnapshotFromRow(&rows[i]); snap != nil {
			items = append(items, *snap)
		}
	}
	return &ForwardMetricsHistoryResponse{
		WorkspaceID:      pc.workspace.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Items:            items,
	}, nil
}

// RefreshWorkspaceForwardNetworkMetrics forces a live Forward metrics fetch and stores it.
//
//encore:api auth method=POST path=/api/workspaces/:id/forward-networks/:networkRef/metrics/refresh
func (s *Service) RefreshWorkspaceForwardNetworkMetrics(ctx context.Context, id, networkRef string) (*ForwardMetricsSummaryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}

	forwardMetricsSyncRunsTotal.With(forwardMetricsSyncSourceLabels{Source: "manual"}).Add(1)
	forwardMetricsLastRunUnix.With(forwardMetricsSyncSourceLabels{Source: "manual"}).Set(float64(time.Now().Unix()))
	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	row, err := forwardMetricsSyncOne(ctxReq, s.db, client, pc.workspace.ID, pc.claims.Username, net.ID, net.ForwardNetworkID, "manual")
	if err != nil {
		forwardMetricsSyncFailuresTotal.With(forwardMetricsSyncSourceLabels{Source: "manual"}).Add(1)
		return nil, errs.B().Code(errs.Unavailable).Msg("forward metrics refresh failed").Err()
	}

	return &ForwardMetricsSummaryResponse{
		WorkspaceID:      pc.workspace.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Snapshot:         forwardMetricsSnapshotFromRow(row),
		Stale:            false,
	}, nil
}

// AdminForwardMetricsSync triggers a best-effort global sync for all known Forward networks.
//
//encore:api auth method=POST path=/api/admin/forward/metrics/sync tag:admin
func (s *Service) AdminForwardMetricsSync(ctx context.Context) (*AdminForwardMetricsSyncResponse, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := syncForwardMetricsCron(ctxReq, s.db, s.cfg); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("forward metrics sync failed").Err()
	}
	return &AdminForwardMetricsSyncResponse{OK: true, At: time.Now().UTC().Format(time.RFC3339)}, nil
}

// GetAdminForwardMetricsPollState returns runtime poll settings and freshness.
//
//encore:api auth method=GET path=/api/admin/forward/metrics/state tag:admin
func (s *Service) GetAdminForwardMetricsPollState(ctx context.Context) (*AdminForwardMetricsPollStateResponse, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	latest := ""
	if s.db != nil {
		var ts sql.NullTime
		err := s.db.QueryRowContext(ctx, `SELECT MAX(collected_at) FROM sf_forward_metrics_snapshots`).Scan(&ts)
		if err == nil && ts.Valid {
			latest = ts.Time.UTC().Format(time.RFC3339)
		}
	}
	return &AdminForwardMetricsPollStateResponse{
		Enabled:           forwardMetricsPollingEnabled(),
		IntervalMinutes:   forwardMetricsPollingIntervalMinutes(),
		LatestCollectedAt: latest,
	}, nil
}
