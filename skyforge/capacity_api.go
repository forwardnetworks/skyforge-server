package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type CapacityPerfProxyResponse struct {
	Body json.RawMessage `json:"body"`
}

func (s *Service) requireDeploymentForwardNetwork(ctx context.Context, workspaceID, deploymentID string) (dep *WorkspaceDeployment, cfgAny map[string]any, forwardNetworkID string, err error) {
	if s == nil || s.db == nil {
		return nil, nil, "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err = s.getWorkspaceDeployment(ctx, workspaceID, deploymentID)
	if err != nil {
		return nil, nil, "", err
	}
	if dep == nil {
		return nil, nil, "", errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	cfgAny, _ = fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	enabled, _ := cfgAny["forwardEnabled"].(bool)
	if !enabled {
		return nil, nil, "", errs.B().Code(errs.FailedPrecondition).Msg("Forward is disabled for this deployment").Err()
	}
	forwardNetworkID, _ = cfgAny["forwardNetworkId"].(string)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if forwardNetworkID == "" {
		return nil, nil, "", errs.B().Code(errs.FailedPrecondition).Msg("Forward network id missing; run Forward sync first").Err()
	}
	return dep, cfgAny, forwardNetworkID, nil
}

func (s *Service) capacityForwardClientForDeployment(ctx context.Context, username string, cfgAny map[string]any) (*forwardClient, error) {
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("unauthenticated").Err()
	}
	collectorID := strings.TrimSpace(fmt.Sprintf("%v", cfgAny["forwardCollectorId"]))
	rec, err := resolveForwardCredentialsFor(ctx, s.db, s.cfg.SessionSecret, "", username, "", forwardCredResolveOpts{
		CollectorConfigID: collectorID,
	})
	if err != nil {
		// Keep capacity semantics: if nothing is configured for the user, surface that directly.
		if errs.Code(err) == errs.FailedPrecondition {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user").Err()
		}
		return nil, err
	}
	client, err := newForwardClient(*rec)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	return client, nil
}

// GetWorkspaceDeploymentCapacitySummary returns the latest stored capacity rollups for a deployment.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/capacity/summary
func (s *Service) GetWorkspaceDeploymentCapacitySummary(ctx context.Context, id, deploymentID string) (*DeploymentCapacitySummaryResponse, error) {
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

	_, _, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	periodEnd, rows, err := loadLatestCapacityRollups(ctx, s.db, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load capacity rollups").Err()
	}
	asOf := ""
	stale := true
	if !periodEnd.IsZero() {
		asOf = periodEnd.UTC().Format(time.RFC3339)
		stale = time.Since(periodEnd) > 2*time.Hour
	}
	return &DeploymentCapacitySummaryResponse{
		WorkspaceID:  pc.workspace.ID,
		DeploymentID: deploymentID,
		ForwardID:    forwardNetworkID,
		AsOf:         asOf,
		Rollups:      rows,
		Stale:        stale,
	}, nil
}

type capacityRollupRefreshRequest struct {
	// Optional override; primarily for debugging.
	// Defaults to the deployment id in the path.
	DeploymentID string `json:"deploymentId,omitempty"`
}

// RefreshWorkspaceDeploymentCapacityRollups enqueues a background rollup task for the deployment.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/capacity/rollups/refresh
func (s *Service) RefreshWorkspaceDeploymentCapacityRollups(ctx context.Context, id, deploymentID string, req *capacityRollupRefreshRequest) (*DeploymentCapacityRefreshResponse, error) {
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

	if req != nil && strings.TrimSpace(req.DeploymentID) != "" {
		deploymentID = strings.TrimSpace(req.DeploymentID)
	}

	_, cfgAny, _, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	// Validate that the current user has Forward credentials before queuing work.
	if _, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny); err != nil {
		return nil, err
	}

	metaAny := map[string]any{"deploymentId": deploymentID}
	meta, _ := toJSONMap(metaAny)
	msg := fmt.Sprintf("Capacity rollup (%s)", pc.claims.Username)
	task, err := createTaskAllowActive(ctx, s.db, pc.workspace.ID, &deploymentID, "capacity-rollup", msg, pc.claims.Username, meta)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to enqueue rollup").Err()
	}
	s.enqueueTask(ctx, task)

	runJSON := JSONMap{}
	if runAny := taskToRunInfo(*task); runAny != nil {
		if converted, err := toJSONMap(runAny); err == nil {
			runJSON = converted
		}
	}
	return &DeploymentCapacityRefreshResponse{
		WorkspaceID:  pc.workspace.ID,
		DeploymentID: deploymentID,
		Run:          runJSON,
	}, nil
}

// ---- Forward perf proxy endpoints (read-through) ----

type CapacityInterfaceMetricsQuery struct {
	Type            string `query:"type"`
	Days            int    `query:"days"`
	Direction       string `query:"direction" encore:"optional"`
	Interface       string `query:"interface" encore:"optional"`
	InterfaceFilter string `query:"interfaceFilter" encore:"optional"`
	SnapshotID      string `query:"snapshotId" encore:"optional"`
	EndTime         string `query:"endTime" encore:"optional"`
}

// GetWorkspaceDeploymentCapacityInterfaceMetrics proxies Forward's interface-metrics endpoint.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/capacity/perf/interface-metrics
func (s *Service) GetWorkspaceDeploymentCapacityInterfaceMetrics(ctx context.Context, id, deploymentID string, q *CapacityInterfaceMetricsQuery) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	_, cfgAny, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny)
	if err != nil {
		return nil, err
	}
	if q == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("query required").Err()
	}
	query := url.Values{}
	query.Set("type", strings.TrimSpace(q.Type))
	if q.Days > 0 {
		query.Set("days", fmt.Sprintf("%d", q.Days))
	}
	if v := strings.TrimSpace(q.Direction); v != "" {
		query.Set("direction", v)
	}
	if v := strings.TrimSpace(q.Interface); v != "" {
		query.Set("interface", v)
	}
	if v := strings.TrimSpace(q.InterfaceFilter); v != "" {
		query.Set("interfaceFilter", v)
	}
	if v := strings.TrimSpace(q.SnapshotID); v != "" {
		query.Set("snapshotId", v)
	}
	if v := strings.TrimSpace(q.EndTime); v != "" {
		query.Set("endTime", v)
	}

	rawPath := "/networks/" + url.PathEscape(forwardNetworkID) + "/interface-metrics"
	resp, body, err := client.doJSON(ctx, "GET", rawPath, query, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

type CapacityInterfaceWithDirection struct {
	DeviceName    string `json:"deviceName"`
	InterfaceName string `json:"interfaceName"`
	Direction     string `json:"direction,omitempty"`
}

type capacityInterfaceMetricsHistoryRequest struct {
	Type       string                           `json:"type"`
	Days       int                              `json:"days,omitempty"`
	StartTime  string                           `json:"startTime,omitempty"`
	EndTime    string                           `json:"endTime,omitempty"`
	MaxSamples int                              `json:"maxSamples,omitempty"`
	Interfaces []CapacityInterfaceWithDirection `json:"interfaces"`
}

type fwdInterfaceMetricsHistoryPayload struct {
	Interfaces []CapacityInterfaceWithDirection `json:"interfaces"`
}

// PostWorkspaceDeploymentCapacityInterfaceMetricsHistory proxies Forward's interface-metrics-history endpoint.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/capacity/perf/interface-metrics-history
func (s *Service) PostWorkspaceDeploymentCapacityInterfaceMetricsHistory(ctx context.Context, id, deploymentID string, req *capacityInterfaceMetricsHistoryRequest) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	_, cfgAny, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	query := url.Values{}
	query.Set("type", strings.TrimSpace(req.Type))
	if req.Days > 0 {
		query.Set("days", fmt.Sprintf("%d", req.Days))
	}
	if v := strings.TrimSpace(req.StartTime); v != "" {
		query.Set("startTime", v)
	}
	if v := strings.TrimSpace(req.EndTime); v != "" {
		query.Set("endTime", v)
	}
	if req.MaxSamples > 0 {
		query.Set("maxSamples", fmt.Sprintf("%d", req.MaxSamples))
	}
	rawPath := "/networks/" + url.PathEscape(forwardNetworkID) + "/interface-metrics-history"
	payload := &fwdInterfaceMetricsHistoryPayload{Interfaces: req.Interfaces}
	resp, body, err := client.doJSON(ctx, "POST", rawPath, query, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

type CapacityDeviceMetricsQuery struct {
	Type       string `query:"type"`
	Days       int    `query:"days"`
	Device     string `query:"device" encore:"optional"`
	SnapshotID string `query:"snapshotId" encore:"optional"`
	EndTime    string `query:"endTime" encore:"optional"`
}

// GetWorkspaceDeploymentCapacityDeviceMetrics proxies Forward's device-metrics endpoint.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/capacity/perf/device-metrics
func (s *Service) GetWorkspaceDeploymentCapacityDeviceMetrics(ctx context.Context, id, deploymentID string, q *CapacityDeviceMetricsQuery) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	_, cfgAny, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny)
	if err != nil {
		return nil, err
	}

	if q == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("query required").Err()
	}
	query := url.Values{}
	query.Set("type", strings.TrimSpace(q.Type))
	if q.Days > 0 {
		query.Set("days", fmt.Sprintf("%d", q.Days))
	}
	if v := strings.TrimSpace(q.Device); v != "" {
		query.Set("device", v)
	}
	if v := strings.TrimSpace(q.SnapshotID); v != "" {
		query.Set("snapshotId", v)
	}
	if v := strings.TrimSpace(q.EndTime); v != "" {
		query.Set("endTime", v)
	}
	rawPath := "/networks/" + url.PathEscape(forwardNetworkID) + "/device-metrics"
	resp, body, err := client.doJSON(ctx, "GET", rawPath, query, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

type capacityDeviceSet struct {
	Type       string   `json:"type"`
	Days       int      `json:"days,omitempty"`
	StartTime  string   `json:"startTime,omitempty"`
	EndTime    string   `json:"endTime,omitempty"`
	MaxSamples int      `json:"maxSamples,omitempty"`
	Devices    []string `json:"devices"`
}

type fwdDeviceSetPayload struct {
	Devices []string `json:"devices"`
}

// PostWorkspaceDeploymentCapacityDeviceMetricsHistory proxies Forward's device-metrics-history endpoint.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/capacity/perf/device-metrics-history
func (s *Service) PostWorkspaceDeploymentCapacityDeviceMetricsHistory(ctx context.Context, id, deploymentID string, req *capacityDeviceSet) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	_, cfgAny, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny)
	if err != nil {
		return nil, err
	}

	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	query := url.Values{}
	query.Set("type", strings.TrimSpace(req.Type))
	if req.Days > 0 {
		query.Set("days", fmt.Sprintf("%d", req.Days))
	}
	if v := strings.TrimSpace(req.StartTime); v != "" {
		query.Set("startTime", v)
	}
	if v := strings.TrimSpace(req.EndTime); v != "" {
		query.Set("endTime", v)
	}
	if req.MaxSamples > 0 {
		query.Set("maxSamples", fmt.Sprintf("%d", req.MaxSamples))
	}
	rawPath := "/networks/" + url.PathEscape(forwardNetworkID) + "/device-metrics-history"
	payload := &fwdDeviceSetPayload{Devices: req.Devices}
	resp, body, err := client.doJSON(ctx, "POST", rawPath, query, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

// ---- Forward health proxy endpoints (read-through) ----

type CapacityUnhealthyDevicesQuery struct {
	SnapshotID string `query:"snapshotId" encore:"optional"`
	EndTime    string `query:"endTime" encore:"optional"`
}

// GetWorkspaceDeploymentCapacityUnhealthyDevices proxies Forward's unhealthy-devices endpoint.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/capacity/perf/unhealthy-devices
func (s *Service) GetWorkspaceDeploymentCapacityUnhealthyDevices(ctx context.Context, id, deploymentID string, q *CapacityUnhealthyDevicesQuery) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	_, cfgAny, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	if q != nil {
		if v := strings.TrimSpace(q.SnapshotID); v != "" {
			query.Set("snapshotId", v)
		}
		if v := strings.TrimSpace(q.EndTime); v != "" {
			query.Set("endTime", v)
		}
	}

	rawPath := "/networks/" + url.PathEscape(forwardNetworkID) + "/unhealthy-devices"
	resp, body, err := client.doJSON(ctx, "GET", rawPath, query, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

type CapacityUnhealthyInterfacesRequest struct {
	SnapshotID string   `query:"snapshotId" encore:"optional"`
	EndTime    string   `query:"endTime" encore:"optional"`
	Devices    []string `json:"devices"`
}

// GetWorkspaceDeploymentCapacityUnhealthyInterfaces proxies Forward's unhealthy-interfaces endpoint.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/capacity/perf/unhealthy-interfaces
func (s *Service) GetWorkspaceDeploymentCapacityUnhealthyInterfaces(ctx context.Context, id, deploymentID string, req *CapacityUnhealthyInterfacesRequest) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	_, cfgAny, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForDeployment(ctx, pc.claims.Username, cfgAny)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	query := url.Values{}
	if req != nil {
		if v := strings.TrimSpace(req.SnapshotID); v != "" {
			query.Set("snapshotId", v)
		}
		if v := strings.TrimSpace(req.EndTime); v != "" {
			query.Set("endTime", v)
		}
	}

	rawPath := "/networks/" + url.PathEscape(forwardNetworkID) + "/unhealthy-interfaces"
	payload := req.Devices
	resp, body, err := client.doJSON(ctx, "POST", rawPath, query, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

// ---- rollup storage ----

func loadLatestCapacityRollups(ctx context.Context, db *sql.DB, workspaceID, deploymentID string) (time.Time, []CapacityRollupRow, error) {
	if db == nil {
		return time.Time{}, nil, fmt.Errorf("db unavailable")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var periodEnd time.Time
	err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND deployment_id=$2`, workspaceID, deploymentID).Scan(&periodEnd)
	if err != nil {
		return time.Time{}, nil, err
	}
	if periodEnd.IsZero() || periodEnd.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, []CapacityRollupRow{}, nil
	}
	rows, err := db.QueryContext(ctxReq, `SELECT forward_network_id, object_type, object_id, metric, window_label,
  period_end, samples, avg, p95, p99, max, slope_per_day, forecast_crossing_ts, threshold, details, created_at
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND deployment_id=$2 AND period_end=$3
ORDER BY metric, window_label, object_type, object_id`, workspaceID, deploymentID, periodEnd)
	if err != nil {
		return time.Time{}, nil, err
	}
	defer rows.Close()
	out := []CapacityRollupRow{}
	for rows.Next() {
		var forwardID string
		var objectType, objectID, metric, window string
		var samples int
		var periodEndTS time.Time
		var avg, p95, p99, max, slope sql.NullFloat64
		var forecast sql.NullTime
		var threshold sql.NullFloat64
		var detailsBytes []byte
		var createdAt time.Time
		if err := rows.Scan(
			&forwardID, &objectType, &objectID, &metric, &window,
			&periodEndTS, &samples, &avg, &p95, &p99, &max, &slope, &forecast, &threshold, &detailsBytes, &createdAt,
		); err != nil {
			continue
		}
		row := CapacityRollupRow{
			WorkspaceID:      workspaceID,
			DeploymentID:     deploymentID,
			ForwardNetworkID: strings.TrimSpace(forwardID),
			ObjectType:       strings.TrimSpace(objectType),
			ObjectID:         strings.TrimSpace(objectID),
			Metric:           strings.TrimSpace(metric),
			Window:           strings.TrimSpace(window),
			PeriodEnd:        periodEndTS.UTC().Format(time.RFC3339),
			Samples:          samples,
			CreatedAt:        createdAt.UTC().Format(time.RFC3339),
		}
		if avg.Valid {
			v := avg.Float64
			row.Avg = &v
		}
		if p95.Valid {
			v := p95.Float64
			row.P95 = &v
		}
		if p99.Valid {
			v := p99.Float64
			row.P99 = &v
		}
		if max.Valid {
			v := max.Float64
			row.Max = &v
		}
		if slope.Valid {
			v := slope.Float64
			row.SlopePerDay = &v
		}
		if forecast.Valid {
			v := forecast.Time.UTC().Format(time.RFC3339)
			row.ForecastCrossingTS = &v
		}
		if threshold.Valid {
			v := threshold.Float64
			row.Threshold = &v
		}
		if len(detailsBytes) > 0 {
			var m JSONMap
			_ = json.Unmarshal(detailsBytes, &m)
			row.Details = m
		}
		out = append(out, row)
	}
	return periodEnd, out, nil
}
