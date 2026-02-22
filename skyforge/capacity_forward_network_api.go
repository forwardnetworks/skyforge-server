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
	UserScopeID      string              `json:"userId"`
	NetworkRef       string              `json:"networkRef"`
	ForwardNetworkID string              `json:"forwardNetworkId"`
	AsOf             string              `json:"asOf,omitempty"`
	Rollups          []CapacityRollupRow `json:"rollups"`
	Stale            bool                `json:"stale"`
}

type ForwardNetworkCapacityRefreshResponse struct {
	UserScopeID string  `json:"userId"`
	NetworkRef  string  `json:"networkRef"`
	Run         JSONMap `json:"run"`
}

type ForwardNetworkCapacityInventoryResponse struct {
	UserScopeID      string `json:"userId"`
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
	UserScopeID      string              `json:"userId"`
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

func resolveUserScopeForwardNetwork(ctx context.Context, db *sql.DB, userScopeID, networkRef string) (*resolveForwardNetworkRow, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	userScopeID = strings.TrimSpace(userScopeID)
	networkRef = strings.TrimSpace(networkRef)
	if userScopeID == "" || networkRef == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid identifiers").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var id, forwardID, collectorConfigID string
	err := db.QueryRowContext(ctxReq, `
SELECT id::text, forward_network_id, COALESCE(collector_config_id,'')
  FROM sf_policy_report_forward_networks
 WHERE user_id=$1 AND (id::text=$2 OR forward_network_id=$2)
 LIMIT 1`, userScopeID, networkRef).Scan(&id, &forwardID, &collectorConfigID)
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

// GetUserScopeForwardNetworkCapacitySummary returns the latest stored capacity rollups for a saved Forward network.
//
//encore:api auth method=GET path=/api/users/:id/forward-networks/:networkRef/capacity/summary
func (s *Service) GetUserScopeForwardNetworkCapacitySummary(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacitySummaryResponse, error) {
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

	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
	if err != nil {
		return nil, err
	}

	periodEnd, rows, err := loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.userScope.ID, net.ForwardNetworkID)
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
		UserScopeID:      pc.userScope.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		AsOf:             asOf,
		Rollups:          rows,
		Stale:            stale,
	}, nil
}

// RefreshUserScopeForwardNetworkCapacityRollups enqueues a background rollup task for the saved Forward network.
//
//encore:api auth method=POST path=/api/users/:id/forward-networks/:networkRef/capacity/rollups/refresh
func (s *Service) RefreshUserScopeForwardNetworkCapacityRollups(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacityRefreshResponse, error) {
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

	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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
	task, err := createTaskAllowActive(ctx, s.db, pc.userScope.ID, nil, "capacity-rollup-forward-network", msg, pc.claims.Username, meta)
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
		UserScopeID: pc.userScope.ID,
		NetworkRef:  net.ID,
		Run:         runJSON,
	}, nil
}

// ---- Inventory ----

// GetUserScopeForwardNetworkCapacityInventory returns the latest cached NQE results for inventory/routing scale.
//
//encore:api auth method=GET path=/api/users/:id/forward-networks/:networkRef/capacity/inventory
func (s *Service) GetUserScopeForwardNetworkCapacityInventory(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacityInventoryResponse, error) {
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

	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
	if err != nil {
		return nil, err
	}

	asOf, snapshotID, devices, ifaces, ifaceVrfs, hwTcam, routes, bgp, err := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.userScope.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load capacity inventory").Err()
	}

	out := &ForwardNetworkCapacityInventoryResponse{
		UserScopeID:      pc.userScope.ID,
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

// GetUserScopeForwardNetworkCapacityGrowth compares the latest rollup bucket to an earlier one and returns deltas.
//
//encore:api auth method=GET path=/api/users/:id/forward-networks/:networkRef/capacity/growth
func (s *Service) GetUserScopeForwardNetworkCapacityGrowth(ctx context.Context, id, networkRef string, q *DeploymentCapacityGrowthQuery) (*ForwardNetworkCapacityGrowthResponse, error) {
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
	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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

	asOf, compareAsOf, rows, err := loadCapacityGrowthForForwardNetwork(ctx, s.db, pc.userScope.ID, net.ForwardNetworkID, metric, window, objectType, time.Duration(compareHours)*time.Hour)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to compute growth").Err()
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	resp := &ForwardNetworkCapacityGrowthResponse{
		UserScopeID:      pc.userScope.ID,
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

// GetUserScopeForwardNetworkCapacityInterfaceMetrics proxies Forward's interface-metrics endpoint.
//
//encore:api auth method=GET path=/api/users/:id/forward-networks/:networkRef/capacity/perf/interface-metrics
func (s *Service) GetUserScopeForwardNetworkCapacityInterfaceMetrics(ctx context.Context, id, networkRef string, q *CapacityInterfaceMetricsQuery) (*CapacityPerfProxyResponse, error) {
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
	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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

// PostUserScopeForwardNetworkCapacityInterfaceMetricsHistory proxies Forward's interface-metrics-history endpoint.
//
//encore:api auth method=POST path=/api/users/:id/forward-networks/:networkRef/capacity/perf/interface-metrics-history
func (s *Service) PostUserScopeForwardNetworkCapacityInterfaceMetricsHistory(ctx context.Context, id, networkRef string, req *capacityInterfaceMetricsHistoryRequest) (*CapacityPerfProxyResponse, error) {
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
	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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

// PostUserScopeForwardNetworkCapacityDeviceMetricsHistory proxies Forward's device-metrics-history endpoint.
//
//encore:api auth method=POST path=/api/users/:id/forward-networks/:networkRef/capacity/perf/device-metrics-history
func (s *Service) PostUserScopeForwardNetworkCapacityDeviceMetricsHistory(ctx context.Context, id, networkRef string, req *capacityDeviceSet) (*CapacityPerfProxyResponse, error) {
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
	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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

// GetUserScopeForwardNetworkCapacityUnhealthyDevices proxies Forward's unhealthy-devices endpoint.
//
//encore:api auth method=GET path=/api/users/:id/forward-networks/:networkRef/capacity/perf/unhealthy-devices
func (s *Service) GetUserScopeForwardNetworkCapacityUnhealthyDevices(ctx context.Context, id, networkRef string, q *CapacityUnhealthyDevicesQuery) (*CapacityPerfProxyResponse, error) {
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
	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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

// PostUserScopeForwardNetworkCapacityUnhealthyInterfaces proxies Forward's unhealthy-interfaces endpoint.
//
//encore:api auth method=POST path=/api/users/:id/forward-networks/:networkRef/capacity/perf/unhealthy-interfaces
func (s *Service) PostUserScopeForwardNetworkCapacityUnhealthyInterfaces(ctx context.Context, id, networkRef string, req *CapacityUnhealthyInterfacesRequest) (*CapacityPerfProxyResponse, error) {
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
	net, err := resolveUserScopeForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef)
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

func loadLatestCapacityRollupsForForwardNetwork(ctx context.Context, db *sql.DB, userScopeID, forwardNetworkID string) (time.Time, []CapacityRollupRow, error) {
	if db == nil {
		return time.Time{}, nil, fmt.Errorf("db unavailable")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if userScopeID == "" || forwardNetworkID == "" {
		return time.Time{}, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var periodEnd time.Time
	err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE user_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL`, userScopeID, forwardNetworkID).Scan(&periodEnd)
	if err != nil {
		return time.Time{}, nil, err
	}
	if periodEnd.IsZero() || periodEnd.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, []CapacityRollupRow{}, nil
	}
	rows, err := db.QueryContext(ctxReq, `SELECT forward_network_id, object_type, object_id, metric, window_label,
  period_end, samples, avg, p95, p99, max, slope_per_day, forecast_crossing_ts, threshold, details, created_at
FROM sf_capacity_rollups
WHERE user_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND period_end=$3
ORDER BY metric, window_label, object_type, object_id`, userScopeID, forwardNetworkID, periodEnd)
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
			UserScopeID:      userScopeID,
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

func loadLatestCapacityInventoryForForwardNetwork(ctx context.Context, db *sql.DB, userScopeID, forwardNetworkID string) (asOf time.Time, snapshotID string, devices []CapacityDeviceInventoryRow, ifaces []CapacityInterfaceInventoryRow, ifaceVrfs []CapacityInterfaceVrfRow, hwTcam []CapacityHardwareTcamRow, routes []CapacityRouteScaleRow, bgp []CapacityBgpNeighborRow, err error) {
	if db == nil {
		return time.Time{}, "", nil, nil, nil, nil, nil, nil, fmt.Errorf("db unavailable")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if userScopeID == "" || forwardNetworkID == "" {
		return time.Time{}, "", nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctxReq, `SELECT DISTINCT ON (query_id) query_id, payload, created_at
FROM sf_capacity_nqe_cache
WHERE user_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND snapshot_id=''
ORDER BY query_id, created_at DESC`, userScopeID, forwardNetworkID)
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

func loadCapacityGrowthForForwardNetwork(ctx context.Context, db *sql.DB, userScopeID, forwardNetworkID, metric, window, objectType string, compareDur time.Duration) (asOf time.Time, compareAsOf time.Time, out []CapacityGrowthRow, err error) {
	if db == nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("db unavailable")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	metric = strings.TrimSpace(metric)
	window = strings.TrimSpace(window)
	objectType = strings.TrimSpace(objectType)
	if userScopeID == "" || forwardNetworkID == "" || metric == "" || window == "" {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE user_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND metric=$3 AND window_label=$4`,
		userScopeID, forwardNetworkID, metric, window).Scan(&asOf); err != nil {
		return time.Time{}, time.Time{}, nil, err
	}
	if asOf.IsZero() || asOf.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, time.Time{}, []CapacityGrowthRow{}, nil
	}

	target := asOf.Add(-compareDur)
	if err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE user_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND metric=$3 AND window_label=$4 AND period_end <= $5`,
		userScopeID, forwardNetworkID, metric, window, target).Scan(&compareAsOf); err != nil {
		return asOf, time.Time{}, nil, err
	}
	if compareAsOf.IsZero() || compareAsOf.Equal(time.Unix(0, 0).UTC()) {
		compareAsOf = time.Time{}
	}

	loadBucket := func(ts time.Time) ([]CapacityRollupRow, error) {
		if ts.IsZero() {
			return []CapacityRollupRow{}, nil
		}
		args := []any{userScopeID, forwardNetworkID, metric, window, ts}
		query := `SELECT forward_network_id, object_type, object_id, metric, window_label,
  period_end, samples, avg, p95, p99, max, slope_per_day, forecast_crossing_ts, threshold, details, created_at
FROM sf_capacity_rollups
WHERE user_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND metric=$3 AND window_label=$4 AND period_end=$5`
		if objectType != "" {
			query += " AND object_type=$6"
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
				UserScopeID:      userScopeID,
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
