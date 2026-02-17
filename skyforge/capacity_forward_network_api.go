package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ForwardNetworkCapacitySummaryResponse struct {
	UserContextID    string              `json:"userContextId"`
	NetworkRef       string              `json:"networkRef"`
	ForwardNetworkID string              `json:"forwardNetworkId"`
	AsOf             string              `json:"asOf,omitempty"`
	Rollups          []CapacityRollupRow `json:"rollups"`
	Stale            bool                `json:"stale"`
}

type ForwardNetworkCapacityRefreshResponse struct {
	UserContextID string  `json:"userContextId"`
	NetworkRef    string  `json:"networkRef"`
	Run           JSONMap `json:"run"`
}

type ForwardNetworkCapacityInventoryResponse struct {
	UserContextID    string `json:"userContextId"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	AsOf             string `json:"asOf,omitempty"`
	SnapshotID       string `json:"snapshotId,omitempty"`

	Devices       []CapacityDeviceInventoryRow    `json:"devices"`
	Interfaces    []CapacityInterfaceInventoryRow `json:"interfaces"`
	InterfaceVrfs []CapacityInterfaceVrfRow       `json:"interfaceVrfs,omitempty"`
	HardwareTcam  []CapacityHardwareTcamRow       `json:"hardwareTcam,omitempty"`
	RouteScale    []CapacityRouteScaleRow         `json:"routeScale"`
	BgpNeighbors  []CapacityBgpNeighborRow        `json:"bgpNeighbors"`
}

type ForwardNetworkCapacityGrowthResponse struct {
	UserContextID    string              `json:"userContextId"`
	NetworkRef       string              `json:"networkRef"`
	ForwardNetworkID string              `json:"forwardNetworkId"`
	Metric           string              `json:"metric"`
	Window           string              `json:"window"`
	ObjectType       string              `json:"objectType,omitempty"`
	AsOf             string              `json:"asOf,omitempty"`
	CompareAsOf      string              `json:"compareAsOf,omitempty"`
	CompareHours     int                 `json:"compareHours"`
	Rows             []CapacityGrowthRow `json:"rows"`
}

type resolveForwardNetworkRow struct {
	ID                string
	ForwardNetworkID  string
	CollectorConfigID string
}

func resolveUserForwardNetwork(ctx context.Context, db *sql.DB, userContextID, username, networkRef string) (*resolveForwardNetworkRow, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	userContextID = strings.TrimSpace(userContextID)
	username = strings.ToLower(strings.TrimSpace(username))
	networkRef = strings.TrimSpace(networkRef)
	if username == "" || networkRef == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid identifiers").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var id, forwardID, collectorConfigID string
	err := db.QueryRowContext(ctxReq, `
WITH me AS (
  SELECT id FROM sf_users WHERE username=$2 LIMIT 1
)
SELECT n.id::text, n.forward_network_id, COALESCE(n.collector_config_id,'')
  FROM sf_policy_report_forward_networks n
  LEFT JOIN me ON true
 WHERE (n.id::text=$3 OR n.forward_network_id=$3)
   AND (
     n.owner_username=$2
     OR (me.id IS NOT NULL AND n.user_id=me.id)
     OR ($1 <> '' AND n.workspace_id=$1)
   )
 ORDER BY
   (n.owner_username=$2) DESC,
   (me.id IS NOT NULL AND n.user_id=me.id) DESC,
   (($1 <> '') AND n.workspace_id=$1) DESC,
   n.updated_at DESC
 LIMIT 1`, userContextID, username, networkRef).Scan(&id, &forwardID, &collectorConfigID)
	if err != nil {
		if err == sql.ErrNoRows || isMissingDBRelation(err) {
			return nil, errs.B().Code(errs.NotFound).Msg("forward network not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load forward network").Err()
	}
	id = strings.TrimSpace(id)
	forwardID = strings.TrimSpace(forwardID)
	collectorConfigID = strings.TrimSpace(collectorConfigID)
	if forwardID == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("forward network not found").Err()
	}
	return &resolveForwardNetworkRow{ID: id, ForwardNetworkID: forwardID, CollectorConfigID: collectorConfigID}, nil
}

func (s *Service) capacityForwardClientForUserNetwork(ctx context.Context, username, collectorConfigID string) (*forwardClient, error) {
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("unauthenticated").Err()
	}

	collectorConfigID = strings.TrimSpace(collectorConfigID)
	var fwdCfg *forwardCredentials
	var err error
	if collectorConfigID != "" {
		fwdCfg, err = s.forwardConfigForUserCollectorConfigID(ctx, username, collectorConfigID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
	}
	if fwdCfg == nil {
		fwdCfg, err = s.forwardConfigForUser(ctx, username)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
	}
	if fwdCfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user").Err()
	}
	client, err := newForwardClient(*fwdCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	return client, nil
}

// ---- Summary / Refresh ----

// GetUserContextForwardNetworkCapacitySummary returns the latest stored capacity rollups for a saved Forward network.
func (s *Service) GetUserContextForwardNetworkCapacitySummary(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacitySummaryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	periodEnd, rows, err := loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.claims.Username, pc.userContext.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load capacity rollups").Err()
	}
	asOf := ""
	stale := true
	if !periodEnd.IsZero() {
		asOf = periodEnd.UTC().Format(time.RFC3339)
		stale = time.Since(periodEnd) > 2*time.Hour
	}
	return &ForwardNetworkCapacitySummaryResponse{
		UserContextID:    pc.userContext.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		AsOf:             asOf,
		Rollups:          rows,
		Stale:            stale,
	}, nil
}

// RefreshUserContextForwardNetworkCapacityRollups enqueues a background rollup task for the saved Forward network.
func (s *Service) RefreshUserContextForwardNetworkCapacityRollups(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacityRefreshResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	// Validate that the current user has Forward credentials before queuing work.
	if _, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID); err != nil {
		return nil, err
	}

	metaAny := map[string]any{
		"forwardNetworkId":  net.ForwardNetworkID,
		"collectorConfigId": net.CollectorConfigID,
	}
	meta, _ := toJSONMap(metaAny)
	msg := fmt.Sprintf("Capacity rollup (%s)", pc.claims.Username)
	task, err := createTaskAllowActive(ctx, s.db, pc.userContext.ID, nil, "capacity-rollup-forward-network", msg, pc.claims.Username, meta)
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
	return &ForwardNetworkCapacityRefreshResponse{
		UserContextID: pc.userContext.ID,
		NetworkRef:    net.ID,
		Run:           runJSON,
	}, nil
}

// ---- Inventory ----

// GetUserContextForwardNetworkCapacityInventory returns the latest cached NQE results for inventory/routing scale.
func (s *Service) GetUserContextForwardNetworkCapacityInventory(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacityInventoryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	asOf, snapshotID, devices, ifaces, ifaceVrfs, hwTcam, routes, bgp, err := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.claims.Username, pc.userContext.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load capacity inventory").Err()
	}

	out := &ForwardNetworkCapacityInventoryResponse{
		UserContextID:    pc.userContext.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Devices:          devices,
		Interfaces:       ifaces,
		InterfaceVrfs:    ifaceVrfs,
		HardwareTcam:     hwTcam,
		RouteScale:       routes,
		BgpNeighbors:     bgp,
	}
	if !asOf.IsZero() {
		out.AsOf = asOf.UTC().Format(time.RFC3339)
	}
	out.SnapshotID = strings.TrimSpace(snapshotID)
	return out, nil
}

// ---- Growth ----

// GetUserContextForwardNetworkCapacityGrowth compares the latest rollup bucket to an earlier one and returns deltas.
func (s *Service) GetUserContextForwardNetworkCapacityGrowth(ctx context.Context, id, networkRef string, q *DeploymentCapacityGrowthQuery) (*ForwardNetworkCapacityGrowthResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	if q == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("query required").Err()
	}
	metric := strings.TrimSpace(q.Metric)
	window := strings.TrimSpace(q.Window)
	if metric == "" || window == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("metric and window are required").Err()
	}
	objectType := strings.TrimSpace(q.ObjectType)
	compareHours := q.CompareHours
	if compareHours <= 0 {
		compareHours = 24 * 7
	}
	limit := q.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	asOf, compareAsOf, rows, err := loadCapacityGrowthForForwardNetwork(ctx, s.db, pc.claims.Username, pc.userContext.ID, net.ForwardNetworkID, metric, window, objectType, time.Duration(compareHours)*time.Hour)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to compute growth").Err()
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	resp := &ForwardNetworkCapacityGrowthResponse{
		UserContextID:    pc.userContext.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Metric:           metric,
		Window:           window,
		ObjectType:       objectType,
		CompareHours:     compareHours,
		Rows:             rows,
	}
	if !asOf.IsZero() {
		resp.AsOf = asOf.UTC().Format(time.RFC3339)
	}
	if !compareAsOf.IsZero() {
		resp.CompareAsOf = compareAsOf.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

// ---- Forward perf proxy endpoints (read-through) ----

// GetUserContextForwardNetworkCapacityInterfaceMetrics proxies Forward's interface-metrics endpoint.
func (s *Service) GetUserContextForwardNetworkCapacityInterfaceMetrics(ctx context.Context, id, networkRef string, q *CapacityInterfaceMetricsQuery) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
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

	rawPath := "/networks/" + url.PathEscape(net.ForwardNetworkID) + "/interface-metrics"
	resp, body, err := client.doJSON(ctx, "GET", rawPath, query, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

// PostUserContextForwardNetworkCapacityInterfaceMetricsHistory proxies Forward's interface-metrics-history endpoint.
func (s *Service) PostUserContextForwardNetworkCapacityInterfaceMetricsHistory(ctx context.Context, id, networkRef string, req *capacityInterfaceMetricsHistoryRequest) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
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
	rawPath := "/networks/" + url.PathEscape(net.ForwardNetworkID) + "/interface-metrics-history"
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

// PostUserContextForwardNetworkCapacityDeviceMetricsHistory proxies Forward's device-metrics-history endpoint.
func (s *Service) PostUserContextForwardNetworkCapacityDeviceMetricsHistory(ctx context.Context, id, networkRef string, req *capacityDeviceSet) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
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
	rawPath := "/networks/" + url.PathEscape(net.ForwardNetworkID) + "/device-metrics-history"
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

// GetUserContextForwardNetworkCapacityUnhealthyDevices proxies Forward's unhealthy-devices endpoint.
func (s *Service) GetUserContextForwardNetworkCapacityUnhealthyDevices(ctx context.Context, id, networkRef string, q *CapacityUnhealthyDevicesQuery) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
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
	rawPath := "/networks/" + url.PathEscape(net.ForwardNetworkID) + "/unhealthy-devices"
	resp, body, err := client.doJSON(ctx, "GET", rawPath, query, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward perf failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &CapacityPerfProxyResponse{Body: body}, nil
}

// PostUserContextForwardNetworkCapacityUnhealthyInterfaces proxies Forward's unhealthy-interfaces endpoint.
func (s *Service) PostUserContextForwardNetworkCapacityUnhealthyInterfaces(ctx context.Context, id, networkRef string, req *CapacityUnhealthyInterfacesRequest) (*CapacityPerfProxyResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
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
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	rawPath := "/networks/" + url.PathEscape(net.ForwardNetworkID) + "/unhealthy-interfaces"
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

// ---- storage helpers (forward network scope) ----

func loadLatestCapacityRollupsForForwardNetwork(ctx context.Context, db *sql.DB, username, userContextID, forwardNetworkID string) (time.Time, []CapacityRollupRow, error) {
	if db == nil {
		return time.Time{}, nil, fmt.Errorf("db unavailable")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if username == "" || forwardNetworkID == "" {
		return time.Time{}, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var periodEnd time.Time
	err := db.QueryRowContext(ctxReq, `WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT COALESCE(MAX(r.period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups r
LEFT JOIN me ON true
WHERE r.forward_network_id=$3
  AND r.deployment_id IS NULL
  AND ((me.id IS NOT NULL AND r.user_id=me.id) OR ($2 <> '' AND r.workspace_id=$2))`, username, userContextID, forwardNetworkID).Scan(&periodEnd)
	if err != nil {
		return time.Time{}, nil, err
	}
	if periodEnd.IsZero() || periodEnd.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, []CapacityRollupRow{}, nil
	}
	rows, err := db.QueryContext(ctxReq, `WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT r.forward_network_id, r.object_type, r.object_id, r.metric, r.window_label,
  period_end, samples, avg, p95, p99, max, slope_per_day, forecast_crossing_ts, threshold, details, created_at
FROM sf_capacity_rollups r
LEFT JOIN me ON true
WHERE r.forward_network_id=$3
  AND r.deployment_id IS NULL
  AND r.period_end=$4
  AND ((me.id IS NOT NULL AND r.user_id=me.id) OR ($2 <> '' AND r.workspace_id=$2))
ORDER BY r.metric, r.window_label, r.object_type, r.object_id`, username, userContextID, forwardNetworkID, periodEnd)
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
			UserContextID:    userContextID,
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

func loadLatestCapacityInventoryForForwardNetwork(ctx context.Context, db *sql.DB, username, userContextID, forwardNetworkID string) (asOf time.Time, snapshotID string, devices []CapacityDeviceInventoryRow, ifaces []CapacityInterfaceInventoryRow, ifaceVrfs []CapacityInterfaceVrfRow, hwTcam []CapacityHardwareTcamRow, routes []CapacityRouteScaleRow, bgp []CapacityBgpNeighborRow, err error) {
	if db == nil {
		return time.Time{}, "", nil, nil, nil, nil, nil, nil, fmt.Errorf("db unavailable")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if username == "" || forwardNetworkID == "" {
		return time.Time{}, "", nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctxReq, `WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT DISTINCT ON (c.query_id) c.query_id, c.payload, c.created_at
FROM sf_capacity_nqe_cache c
LEFT JOIN me ON true
WHERE c.forward_network_id=$3
  AND c.deployment_id IS NULL
  AND c.snapshot_id=''
  AND ((me.id IS NOT NULL AND c.user_id=me.id) OR ($2 <> '' AND c.workspace_id=$2))
ORDER BY c.query_id, c.created_at DESC`, username, userContextID, forwardNetworkID)
	if err != nil {
		return time.Time{}, "", nil, nil, nil, nil, nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var qid string
		var payloadBytes []byte
		var createdAt time.Time
		if scanErr := rows.Scan(&qid, &payloadBytes, &createdAt); scanErr != nil {
			continue
		}
		qid = strings.TrimSpace(qid)
		if createdAt.After(asOf) {
			asOf = createdAt
		}
		var cached capacityCachedNQEResponse
		if len(payloadBytes) > 0 {
			_ = json.Unmarshal(payloadBytes, &cached)
		}
		if snapshotID == "" && strings.TrimSpace(cached.SnapshotID) != "" {
			snapshotID = strings.TrimSpace(cached.SnapshotID)
		}
		switch qid {
		case "capacity-devices.nqe":
			var out []CapacityDeviceInventoryRow
			_ = json.Unmarshal(cached.Results, &out)
			devices = out
		case "capacity-interfaces.nqe":
			var out []CapacityInterfaceInventoryRow
			_ = json.Unmarshal(cached.Results, &out)
			ifaces = out
		case "capacity-interface-vrfs.nqe":
			var out []CapacityInterfaceVrfRow
			_ = json.Unmarshal(cached.Results, &out)
			ifaceVrfs = out
		case "capacity-hardware-tcam.nqe":
			var out []CapacityHardwareTcamRow
			_ = json.Unmarshal(cached.Results, &out)
			hwTcam = out
		case "capacity-route-scale.nqe":
			var out []CapacityRouteScaleRow
			_ = json.Unmarshal(cached.Results, &out)
			routes = out
		case "capacity-bgp-neighbors.nqe":
			var out []CapacityBgpNeighborRow
			_ = json.Unmarshal(cached.Results, &out)
			bgp = out
		default:
			continue
		}
	}
	return asOf, snapshotID, devices, ifaces, ifaceVrfs, hwTcam, routes, bgp, nil
}

func loadCapacityGrowthForForwardNetwork(ctx context.Context, db *sql.DB, username, userContextID, forwardNetworkID, metric, window, objectType string, compareDur time.Duration) (asOf time.Time, compareAsOf time.Time, out []CapacityGrowthRow, err error) {
	if db == nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("db unavailable")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	metric = strings.TrimSpace(metric)
	window = strings.TrimSpace(window)
	objectType = strings.TrimSpace(objectType)
	if username == "" || forwardNetworkID == "" || metric == "" || window == "" {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.QueryRowContext(ctxReq, `WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT COALESCE(MAX(r.period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups r
LEFT JOIN me ON true
WHERE r.forward_network_id=$3
  AND r.deployment_id IS NULL
  AND r.metric=$4
  AND r.window_label=$5
  AND ((me.id IS NOT NULL AND r.user_id=me.id) OR ($2 <> '' AND r.workspace_id=$2))`,
		username, userContextID, forwardNetworkID, metric, window).Scan(&asOf); err != nil {
		return time.Time{}, time.Time{}, nil, err
	}
	if asOf.IsZero() || asOf.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, time.Time{}, []CapacityGrowthRow{}, nil
	}

	target := asOf.Add(-compareDur)
	if err := db.QueryRowContext(ctxReq, `WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT COALESCE(MAX(r.period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups r
LEFT JOIN me ON true
WHERE r.forward_network_id=$3
  AND r.deployment_id IS NULL
  AND r.metric=$4
  AND r.window_label=$5
  AND r.period_end <= $6
  AND ((me.id IS NOT NULL AND r.user_id=me.id) OR ($2 <> '' AND r.workspace_id=$2))`,
		username, userContextID, forwardNetworkID, metric, window, target).Scan(&compareAsOf); err != nil {
		return asOf, time.Time{}, nil, err
	}
	if compareAsOf.IsZero() || compareAsOf.Equal(time.Unix(0, 0).UTC()) {
		compareAsOf = time.Time{}
	}

	loadBucket := func(ts time.Time) ([]CapacityRollupRow, error) {
		if ts.IsZero() {
			return []CapacityRollupRow{}, nil
		}
		args := []any{username, userContextID, forwardNetworkID, metric, window, ts}
		query := `WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT r.forward_network_id, r.object_type, r.object_id, r.metric, r.window_label,
  period_end, samples, avg, p95, p99, max, slope_per_day, forecast_crossing_ts, threshold, details, created_at
FROM sf_capacity_rollups r
LEFT JOIN me ON true
WHERE r.forward_network_id=$3
  AND r.deployment_id IS NULL
  AND r.metric=$4
  AND r.window_label=$5
  AND r.period_end=$6
  AND ((me.id IS NOT NULL AND r.user_id=me.id) OR ($2 <> '' AND r.workspace_id=$2))`
		if objectType != "" {
			query += " AND r.object_type=$7"
			args = append(args, objectType)
		}
		rows, err := db.QueryContext(ctxReq, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []CapacityRollupRow{}
		for rows.Next() {
			var forwardID string
			var ot, oid, m, w string
			var samples int
			var periodEndTS time.Time
			var avg, p95, p99, max, slope sql.NullFloat64
			var forecast sql.NullTime
			var threshold sql.NullFloat64
			var detailsBytes []byte
			var createdAt time.Time
			if err := rows.Scan(
				&forwardID, &ot, &oid, &m, &w,
				&periodEndTS, &samples, &avg, &p95, &p99, &max, &slope, &forecast, &threshold, &detailsBytes, &createdAt,
			); err != nil {
				continue
			}
			row := CapacityRollupRow{
				UserContextID:    userContextID,
				ForwardNetworkID: strings.TrimSpace(forwardID),
				ObjectType:       strings.TrimSpace(ot),
				ObjectID:         strings.TrimSpace(oid),
				Metric:           strings.TrimSpace(m),
				Window:           strings.TrimSpace(w),
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
				var dm JSONMap
				_ = json.Unmarshal(detailsBytes, &dm)
				row.Details = dm
			}
			out = append(out, row)
		}
		return out, nil
	}

	nowRows, err := loadBucket(asOf)
	if err != nil {
		return asOf, compareAsOf, nil, err
	}
	prevRows, err := loadBucket(compareAsOf)
	if err != nil {
		return asOf, compareAsOf, nil, err
	}

	prevByKey := map[string]CapacityRollupRow{}
	for _, r := range prevRows {
		key := r.ObjectType + "|" + r.ObjectID
		prevByKey[key] = r
	}

	out = make([]CapacityGrowthRow, 0, len(nowRows))
	for _, r := range nowRows {
		key := r.ObjectType + "|" + r.ObjectID
		var prev *CapacityRollupRow
		if pr, ok := prevByKey[key]; ok {
			cp := pr
			prev = &cp
		}
		row := CapacityGrowthRow{
			ObjectType: r.ObjectType,
			ObjectID:   r.ObjectID,
			Metric:     r.Metric,
			Window:     r.Window,
			Now:        r,
			Prev:       prev,
		}
		if prev != nil && r.P95 != nil && prev.P95 != nil {
			d := *r.P95 - *prev.P95
			row.DeltaP95 = &d
		}
		if prev != nil && r.Max != nil && prev.Max != nil {
			d := *r.Max - *prev.Max
			row.DeltaMax = &d
		}

		// If this is utilization and we have speedMbps, compute delta Gbps for p95.
		//
		// Note: Details is a JSONMap (map[string]json.RawMessage), so we must unmarshal to read values.
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(metric)), "util_") && row.DeltaP95 != nil {
			if r.Details != nil {
				if raw, ok := r.Details["speedMbps"]; ok && len(raw) > 0 {
					speed := 0.0
					var asAny any
					if err := json.Unmarshal(raw, &asAny); err == nil {
						switch v := asAny.(type) {
						case float64:
							speed = v
						case string:
							if parsed, _ := strconv.ParseFloat(strings.TrimSpace(v), 64); parsed > 0 {
								speed = parsed
							}
						}
					}
					if speed > 0 {
						gbps := (*row.DeltaP95 * speed) / 1000.0
						row.DeltaP95Gbps = &gbps
					}
				}
			}
		}
		out = append(out, row)
	}

	sort.Slice(out, func(i, j int) bool {
		di := 0.0
		dj := 0.0
		if out[i].DeltaP95 != nil {
			di = *out[i].DeltaP95
		}
		if out[j].DeltaP95 != nil {
			dj = *out[j].DeltaP95
		}
		return dj < di // desc
	})
	return asOf, compareAsOf, out, nil
}
