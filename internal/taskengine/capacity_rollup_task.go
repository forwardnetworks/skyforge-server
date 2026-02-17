package taskengine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type capacityRollupTaskSpec struct {
	DeploymentID string `json:"deploymentId,omitempty"`
}

type windowSpec struct {
	Label string
	Days  int
}

func (e *Engine) dispatchCapacityRollupTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if e == nil || task == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}

	var specIn capacityRollupTaskSpec
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

	deploymentID := strings.TrimSpace(specIn.DeploymentID)
	if deploymentID == "" && task.DeploymentID.Valid {
		deploymentID = strings.TrimSpace(task.DeploymentID.String)
	}
	if deploymentID == "" {
		return fmt.Errorf("deployment id is required")
	}

	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "capacity.rollup", func() error {
		return e.runCapacityRollup(ctx, pc, deploymentID, task.ID, log)
	})
}

type fwdInterfaceMetric struct {
	DeviceName    string  `json:"deviceName"`
	InterfaceName string  `json:"interfaceName"`
	Direction     string  `json:"direction"`
	Value         float64 `json:"value"`
}

type fwdInterfaceMetricsResponse struct {
	Metrics []fwdInterfaceMetric `json:"metrics"`
}

type fwdInterfaceWithDirection struct {
	DeviceName    string `json:"deviceName"`
	InterfaceName string `json:"interfaceName"`
	Direction     string `json:"direction"`
}

type fwdDataPoint struct {
	Instant string  `json:"instant"`
	Value   float64 `json:"value"`
}

type fwdInterfaceMetricHistory struct {
	InterfaceWithDirection fwdInterfaceWithDirection `json:"interfaceWithDirection"`
	Data                   []fwdDataPoint            `json:"data"`
}

type fwdInterfaceMetricHistoryResponse struct {
	Metrics []fwdInterfaceMetricHistory `json:"metrics"`
}

type fwdDeviceMetric struct {
	DeviceName string  `json:"deviceName"`
	Value      float64 `json:"value"`
}

type fwdDeviceMetricsResponse struct {
	Metrics []fwdDeviceMetric `json:"metrics"`
}

type fwdDeviceMetricHistory struct {
	DeviceName string         `json:"deviceName"`
	Data       []fwdDataPoint `json:"data"`
}

type fwdDeviceMetricHistoryResponse struct {
	Metrics []fwdDeviceMetricHistory `json:"metrics"`
}

func (e *Engine) runCapacityRollup(ctx context.Context, pc *userContext, deploymentID string, taskID int, log Logger) error {
	if e == nil || e.db == nil {
		return fmt.Errorf("engine unavailable")
	}
	if pc == nil {
		return fmt.Errorf("user context unavailable")
	}
	dep, err := e.loadDeployment(ctx, pc.userContext.ID, deploymentID)
	if err != nil {
		return err
	}
	if dep == nil {
		return fmt.Errorf("deployment not found")
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	enabled, _ := cfgAny[forwardEnabledKey].(bool)
	if !enabled {
		return fmt.Errorf("Forward disabled for this deployment")
	}
	networkID := strings.TrimSpace(fmt.Sprintf("%v", cfgAny[forwardNetworkIDKey]))
	if networkID == "" {
		return fmt.Errorf("Forward network id missing")
	}

	collectorConfigID := strings.TrimSpace(fmt.Sprintf("%v", cfgAny[forwardCollectorIDKey]))
	fwdCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil {
		return err
	}
	if fwdCfg == nil {
		return fmt.Errorf("Forward credentials missing for user")
	}
	client, err := newForwardClient(forwardCredentials{BaseURL: fwdCfg.BaseURL, Username: fwdCfg.Username, Password: fwdCfg.Password})
	if err != nil {
		return err
	}

	// Bucket to the hour so "refresh" runs update the current hour instead of endlessly adding near-duplicate runs.
	periodEnd := time.Now().UTC().Truncate(time.Hour)
	log.Infof("Capacity rollup start (deploymentId=%s networkId=%s asOf=%s)", deploymentID, networkID, periodEnd.Format(time.RFC3339))
	windows := []windowSpec{
		{Label: "24h", Days: 1},
		{Label: "7d", Days: 7},
		{Label: "30d", Days: 30},
	}

	// Refresh NQE cache and load lightweight enrichment maps.
	inv, invErr := e.refreshCapacityInventoryCache(ctx, e.db, client, pc.userContext.ID, &deploymentID, networkID, log)
	if invErr != nil && log != nil {
		log.Errorf("capacity inventory refresh failed: %v", invErr)
	}

	// Compute interface rollups for INGRESS/EGRESS.
	for _, w := range windows {
		threshold := 0.85 // ratio in [0..1]; stays consistent with Forward utilization semantics
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "UTILIZATION", "util_ingress", "INGRESS", &threshold, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "UTILIZATION", "INGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "UTILIZATION", "util_egress", "EGRESS", &threshold, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "UTILIZATION", "EGRESS", err)
		}

		// Interface error rate and packet loss (best-effort).
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "ERROR", "if_error_ingress", "INGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "ERROR", "INGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "ERROR", "if_error_egress", "EGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "ERROR", "EGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "PACKET_LOSS", "if_packet_loss_ingress", "INGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "PACKET_LOSS", "INGRESS", err)
		}
		if err := e.rollupInterfaceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "PACKET_LOSS", "if_packet_loss_egress", "EGRESS", nil, inv, taskID, log); err != nil {
			log.Errorf("interface rollup failed (window=%s type=%s dir=%s): %v", w.Label, "PACKET_LOSS", "EGRESS", err)
		}

		// CPU + memory devices.
		if err := e.rollupDeviceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "CPU", inv, taskID, log); err != nil {
			log.Errorf("device rollup failed (window=%s type=%s): %v", w.Label, "CPU", err)
		}
		if err := e.rollupDeviceMetric(ctx, client, pc.userContext.ID, &deploymentID, networkID, periodEnd, w, "MEMORY", inv, taskID, log); err != nil {
			log.Errorf("device rollup failed (window=%s type=%s): %v", w.Label, "MEMORY", err)
		}
	}

	// Record a lightweight task event for UI visibility.
	_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "capacity.rollup.completed", map[string]any{
		"deploymentId": deploymentID,
		"networkId":    networkID,
		"asOf":         periodEnd.Format(time.RFC3339),
	})
	return nil
}

func (e *Engine) rollupInterfaceMetric(
	ctx context.Context,
	client *forwardClient,
	workspaceID string, deploymentID *string, networkID string,
	periodEnd time.Time,
	w windowSpec,
	metricType string,
	metricName string,
	direction string,
	threshold *float64,
	inv *capacityInventoryEnrichment,
	taskID int,
	log Logger,
) error {
	if client == nil {
		return fmt.Errorf("Forward client unavailable")
	}
	query := url.Values{}
	query.Set("type", strings.TrimSpace(metricType))
	query.Set("days", fmt.Sprintf("%d", w.Days))
	query.Set("direction", direction)
	path := "/networks/" + url.PathEscape(networkID) + "/interface-metrics"
	resp, body, err := client.doJSON(ctx, "GET", path, query, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward interface-metrics failed: %s", strings.TrimSpace(string(body)))
	}
	var top fwdInterfaceMetricsResponse
	if err := json.Unmarshal(body, &top); err != nil {
		return err
	}
	metrics := top.Metrics
	if len(metrics) == 0 {
		return nil
	}
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].Value > metrics[j].Value })

	// Watchlist size for time series computations.
	//
	// We compute percentiles/slope/forecast only for a subset to keep per-rollup cost bounded.
	watchN := 10
	if strings.EqualFold(strings.TrimSpace(metricType), "UTILIZATION") {
		watchN = 50
	}
	if watchN > len(metrics) {
		watchN = len(metrics)
	}
	watch := metrics[:watchN]

	// Fetch time series for watchlist and compute percentiles + forecast.
	hq := url.Values{}
	hq.Set("type", strings.TrimSpace(metricType))
	hq.Set("days", fmt.Sprintf("%d", w.Days))
	hq.Set("maxSamples", "400")
	hpath := "/networks/" + url.PathEscape(networkID) + "/interface-metrics-history"
	var hist fwdInterfaceMetricHistoryResponse
	const chunkN = 25
	for i := 0; i < len(watch); i += chunkN {
		end := i + chunkN
		if end > len(watch) {
			end = len(watch)
		}
		payload := map[string]any{
			"interfaces": []map[string]any{},
		}
		for _, m := range watch[i:end] {
			payload["interfaces"] = append(payload["interfaces"].([]map[string]any), map[string]any{
				"deviceName":    strings.TrimSpace(m.DeviceName),
				"interfaceName": strings.TrimSpace(m.InterfaceName),
				"direction":     strings.TrimSpace(m.Direction),
			})
		}
		hresp, hbody, err := client.doJSON(ctx, "POST", hpath, hq, payload)
		if err != nil {
			return err
		}
		if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
			return fmt.Errorf("forward interface-metrics-history failed: %s", strings.TrimSpace(string(hbody)))
		}
		var part fwdInterfaceMetricHistoryResponse
		if err := json.Unmarshal(hbody, &part); err != nil {
			return err
		}
		hist.Metrics = append(hist.Metrics, part.Metrics...)
	}

	for _, m := range metrics {
		objID := fmt.Sprintf("%s:%s:%s", strings.TrimSpace(m.DeviceName), strings.TrimSpace(m.InterfaceName), strings.TrimSpace(m.Direction))
		row := capacityRollupInsert{
			WorkspaceID:      workspaceID,
			DeploymentID:     deploymentID,
			ForwardNetworkID: networkID,
			ObjectType:       "interface",
			ObjectID:         objID,
			Metric:           metricName,
			Window:           w.Label,
			PeriodEnd:        periodEnd,
			Samples:          0,
			Max:              sql.NullFloat64{Valid: true, Float64: m.Value},
			Details: map[string]any{
				"deviceName":    strings.TrimSpace(m.DeviceName),
				"interfaceName": strings.TrimSpace(m.InterfaceName),
				"direction":     strings.TrimSpace(m.Direction),
				"type":          strings.TrimSpace(metricType),
				"source":        "forward",
			},
		}
		if threshold != nil {
			row.Threshold = sql.NullFloat64{Valid: true, Float64: *threshold}
		}

		// Enrich with inventory data if present.
		if inv != nil {
			key := strings.TrimSpace(m.DeviceName) + ":" + strings.TrimSpace(m.InterfaceName)
			if meta, ok := inv.IfaceByKey[key]; ok {
				if meta.DeviceLocationName != nil && strings.TrimSpace(*meta.DeviceLocationName) != "" {
					row.Details["locationName"] = strings.TrimSpace(*meta.DeviceLocationName)
				}
				if len(meta.DeviceTagNames) > 0 {
					row.Details["tagNames"] = meta.DeviceTagNames
				}
				if len(meta.DeviceGroupNames) > 0 {
					row.Details["groupNames"] = meta.DeviceGroupNames
				}
				if meta.SpeedMbps != nil {
					row.Details["speedMbps"] = *meta.SpeedMbps
				}
				if meta.Description != nil && strings.TrimSpace(*meta.Description) != "" {
					row.Details["description"] = strings.TrimSpace(*meta.Description)
				}
				if strings.TrimSpace(meta.AdminStatus) != "" {
					row.Details["adminStatus"] = strings.TrimSpace(meta.AdminStatus)
				}
				if strings.TrimSpace(meta.OperStatus) != "" {
					row.Details["operStatus"] = strings.TrimSpace(meta.OperStatus)
				}
			}
			if vrfs := inv.IfaceVrfsByKey[key]; len(vrfs) > 0 {
				// Store all VRF names; most UIs treat "VRF" as a single value but in practice
				// an interface can be referenced by multiple network instances.
				row.Details["vrfNames"] = vrfs
				if len(vrfs) == 1 {
					row.Details["vrf"] = vrfs[0]
				}
			}
		}

		// Add computed stats if this interface is in the time-series response.
		for _, hm := range hist.Metrics {
			if !strings.EqualFold(strings.TrimSpace(hm.InterfaceWithDirection.DeviceName), strings.TrimSpace(m.DeviceName)) {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(hm.InterfaceWithDirection.InterfaceName), strings.TrimSpace(m.InterfaceName)) {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(hm.InterfaceWithDirection.Direction), strings.TrimSpace(m.Direction)) {
				continue
			}
			values := make([]float64, 0, len(hm.Data))
			xDays := make([]float64, 0, len(hm.Data))
			y := make([]float64, 0, len(hm.Data))
			var t0 time.Time
			for i, dp := range hm.Data {
				ts, err := time.Parse(time.RFC3339, strings.TrimSpace(dp.Instant))
				if err != nil {
					continue
				}
				if i == 0 || t0.IsZero() {
					t0 = ts
				}
				values = append(values, dp.Value)
				xDays = append(xDays, ts.Sub(t0).Seconds()/86400.0)
				y = append(y, dp.Value)
			}
			row.Samples = len(values)
			if len(values) > 0 {
				avg := mean(values)
				p95 := quantile(values, 0.95)
				p99 := quantile(values, 0.99)
				maxV := max(values)
				row.Avg = sql.NullFloat64{Valid: true, Float64: avg}
				row.P95 = sql.NullFloat64{Valid: true, Float64: p95}
				row.P99 = sql.NullFloat64{Valid: true, Float64: p99}
				row.Max = sql.NullFloat64{Valid: true, Float64: math.Max(row.Max.Float64, maxV)}
				slope, _ := linregSlope(xDays, y)
				if !math.IsNaN(slope) && !math.IsInf(slope, 0) {
					row.SlopePerDay = sql.NullFloat64{Valid: true, Float64: slope}
				}
				if threshold != nil && slope > 0 && p95 < *threshold {
					daysToCross := (*threshold - p95) / slope
					if daysToCross > 0 && daysToCross < 3650 {
						cross := periodEnd.Add(time.Duration(daysToCross * 24 * float64(time.Hour)))
						row.ForecastCrossingTS = sql.NullTime{Valid: true, Time: cross}
					}
				}
			}
			break
		}

		if err := insertCapacityRollup(ctx, e.db, row); err != nil {
			// Best effort: continue.
			if log != nil {
				log.Errorf("failed to insert rollup (object=%s window=%s): %v", objID, w.Label, err)
			}
		}
	}
	log.Infof("Capacity interface rollup stored (window=%s type=%s dir=%s total=%d watch=%d)", w.Label, metricType, direction, len(metrics), watchN)
	_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "capacity.rollup.interface", map[string]any{
		"window":     w.Label,
		"type":       metricType,
		"direction":  direction,
		"metric":     metricName,
		"countTotal": len(metrics),
		"countWatch": watchN,
	})
	return nil
}

func (e *Engine) rollupDeviceMetric(
	ctx context.Context,
	client *forwardClient,
	workspaceID string, deploymentID *string, networkID string,
	periodEnd time.Time,
	w windowSpec,
	typ string,
	inv *capacityInventoryEnrichment,
	taskID int,
	log Logger,
) error {
	if client == nil {
		return fmt.Errorf("Forward client unavailable")
	}
	query := url.Values{}
	query.Set("type", strings.ToUpper(strings.TrimSpace(typ)))
	query.Set("days", fmt.Sprintf("%d", w.Days))
	path := "/networks/" + url.PathEscape(networkID) + "/device-metrics"
	resp, body, err := client.doJSON(ctx, "GET", path, query, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward device-metrics failed: %s", strings.TrimSpace(string(body)))
	}
	var top fwdDeviceMetricsResponse
	if err := json.Unmarshal(body, &top); err != nil {
		return err
	}
	metrics := top.Metrics
	if len(metrics) == 0 {
		return nil
	}
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].Value > metrics[j].Value })

	watchN := 50
	if watchN > len(metrics) {
		watchN = len(metrics)
	}
	watch := metrics[:watchN]

	hq := url.Values{}
	hq.Set("type", strings.ToUpper(strings.TrimSpace(typ)))
	hq.Set("days", fmt.Sprintf("%d", w.Days))
	hq.Set("maxSamples", "400")
	hpath := "/networks/" + url.PathEscape(networkID) + "/device-metrics-history"
	var hist fwdDeviceMetricHistoryResponse
	const chunkN = 25
	for i := 0; i < len(watch); i += chunkN {
		end := i + chunkN
		if end > len(watch) {
			end = len(watch)
		}
		payload := map[string]any{
			"devices": []string{},
		}
		for _, m := range watch[i:end] {
			payload["devices"] = append(payload["devices"].([]string), strings.TrimSpace(m.DeviceName))
		}
		hresp, hbody, err := client.doJSON(ctx, "POST", hpath, hq, payload)
		if err != nil {
			return err
		}
		if hresp.StatusCode < 200 || hresp.StatusCode >= 300 {
			return fmt.Errorf("forward device-metrics-history failed: %s", strings.TrimSpace(string(hbody)))
		}
		var part fwdDeviceMetricHistoryResponse
		if err := json.Unmarshal(hbody, &part); err != nil {
			return err
		}
		hist.Metrics = append(hist.Metrics, part.Metrics...)
	}

	metricName := "device_" + strings.ToLower(strings.TrimSpace(typ))
	threshold := 0.85

	for _, m := range metrics {
		objID := strings.TrimSpace(m.DeviceName)
		row := capacityRollupInsert{
			WorkspaceID:      workspaceID,
			DeploymentID:     deploymentID,
			ForwardNetworkID: networkID,
			ObjectType:       "device",
			ObjectID:         objID,
			Metric:           metricName,
			Window:           w.Label,
			PeriodEnd:        periodEnd,
			Samples:          0,
			Max:              sql.NullFloat64{Valid: true, Float64: m.Value},
			Threshold:        sql.NullFloat64{Valid: true, Float64: threshold},
			Details: map[string]any{
				"deviceName": strings.TrimSpace(m.DeviceName),
				"type":       strings.TrimSpace(typ),
				"source":     "forward",
			},
		}

		if inv != nil {
			if meta, ok := inv.DeviceByName[objID]; ok {
				if meta.LocationName != nil && strings.TrimSpace(*meta.LocationName) != "" {
					row.Details["locationName"] = strings.TrimSpace(*meta.LocationName)
				}
				if len(meta.TagNames) > 0 {
					row.Details["tagNames"] = meta.TagNames
				}
				if len(meta.GroupNames) > 0 {
					row.Details["groupNames"] = meta.GroupNames
				}
				if strings.TrimSpace(meta.Vendor) != "" {
					row.Details["vendor"] = strings.TrimSpace(meta.Vendor)
				}
				if strings.TrimSpace(meta.OS) != "" {
					row.Details["os"] = strings.TrimSpace(meta.OS)
				}
				if meta.Model != nil && strings.TrimSpace(*meta.Model) != "" {
					row.Details["model"] = strings.TrimSpace(*meta.Model)
				}
				if meta.OSVersion != nil && strings.TrimSpace(*meta.OSVersion) != "" {
					row.Details["osVersion"] = strings.TrimSpace(*meta.OSVersion)
				}
			}
		}

		for _, hm := range hist.Metrics {
			if !strings.EqualFold(strings.TrimSpace(hm.DeviceName), strings.TrimSpace(m.DeviceName)) {
				continue
			}
			values := make([]float64, 0, len(hm.Data))
			xDays := make([]float64, 0, len(hm.Data))
			y := make([]float64, 0, len(hm.Data))
			var t0 time.Time
			for i, dp := range hm.Data {
				ts, err := time.Parse(time.RFC3339, strings.TrimSpace(dp.Instant))
				if err != nil {
					continue
				}
				if i == 0 || t0.IsZero() {
					t0 = ts
				}
				values = append(values, dp.Value)
				xDays = append(xDays, ts.Sub(t0).Seconds()/86400.0)
				y = append(y, dp.Value)
			}
			row.Samples = len(values)
			if len(values) > 0 {
				avg := mean(values)
				p95 := quantile(values, 0.95)
				p99 := quantile(values, 0.99)
				maxV := max(values)
				row.Avg = sql.NullFloat64{Valid: true, Float64: avg}
				row.P95 = sql.NullFloat64{Valid: true, Float64: p95}
				row.P99 = sql.NullFloat64{Valid: true, Float64: p99}
				row.Max = sql.NullFloat64{Valid: true, Float64: math.Max(row.Max.Float64, maxV)}
				slope, _ := linregSlope(xDays, y)
				if !math.IsNaN(slope) && !math.IsInf(slope, 0) {
					row.SlopePerDay = sql.NullFloat64{Valid: true, Float64: slope}
				}
				if slope > 0 && p95 < threshold {
					daysToCross := (threshold - p95) / slope
					if daysToCross > 0 && daysToCross < 3650 {
						cross := periodEnd.Add(time.Duration(daysToCross * 24 * float64(time.Hour)))
						row.ForecastCrossingTS = sql.NullTime{Valid: true, Time: cross}
					}
				}
			}
			break
		}

		if err := insertCapacityRollup(ctx, e.db, row); err != nil {
			if log != nil {
				log.Errorf("failed to insert rollup (device=%s window=%s): %v", objID, w.Label, err)
			}
		}
	}
	log.Infof("Capacity device rollup stored (window=%s type=%s total=%d watch=%d)", w.Label, typ, len(metrics), watchN)
	_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "capacity.rollup.device", map[string]any{
		"window":     w.Label,
		"type":       typ,
		"metric":     metricName,
		"countTotal": len(metrics),
		"countWatch": watchN,
	})
	return nil
}

type capacityRollupInsert struct {
	WorkspaceID        string
	DeploymentID       *string
	ForwardNetworkID   string
	ObjectType         string
	ObjectID           string
	Metric             string
	Window             string
	PeriodEnd          time.Time
	Samples            int
	Avg                sql.NullFloat64
	P95                sql.NullFloat64
	P99                sql.NullFloat64
	Max                sql.NullFloat64
	SlopePerDay        sql.NullFloat64
	ForecastCrossingTS sql.NullTime
	Threshold          sql.NullFloat64
	Details            map[string]any
}

func insertCapacityRollup(ctx context.Context, db *sql.DB, row capacityRollupInsert) error {
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	detailsBytes, _ := json.Marshal(row.Details)
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var depVal any
	if row.DeploymentID != nil && strings.TrimSpace(*row.DeploymentID) != "" {
		depVal = strings.TrimSpace(*row.DeploymentID)
	}

	var err error
	if depVal != nil {
		_, err = db.ExecContext(ctxReq, `INSERT INTO sf_capacity_rollups (
	  workspace_id, deployment_id, forward_network_id,
	  object_type, object_id, metric, window_label,
	  period_end, samples, avg, p95, p99, max,
	  slope_per_day, forecast_crossing_ts, threshold, details
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
	ON CONFLICT (workspace_id, deployment_id, object_type, object_id, metric, window_label, period_end)
	DO UPDATE SET
	  forward_network_id = EXCLUDED.forward_network_id,
	  samples = EXCLUDED.samples,
	  avg = EXCLUDED.avg,
  p95 = EXCLUDED.p95,
  p99 = EXCLUDED.p99,
  max = EXCLUDED.max,
  slope_per_day = EXCLUDED.slope_per_day,
  forecast_crossing_ts = EXCLUDED.forecast_crossing_ts,
  threshold = EXCLUDED.threshold,
  details = EXCLUDED.details,
  created_at = now()`,
			row.WorkspaceID, depVal, row.ForwardNetworkID,
			row.ObjectType, row.ObjectID, row.Metric, row.Window,
			row.PeriodEnd, row.Samples, nullFloatPtr(row.Avg), nullFloatPtr(row.P95), nullFloatPtr(row.P99), nullFloatPtr(row.Max),
			nullFloatPtr(row.SlopePerDay), nullTimePtr(row.ForecastCrossingTS), nullFloatPtr(row.Threshold), detailsBytes,
		)
		return err
	}

	// Network-scoped rollup row (deployment_id IS NULL).
	_, err = db.ExecContext(ctxReq, `INSERT INTO sf_capacity_rollups (
  workspace_id, deployment_id, forward_network_id,
  object_type, object_id, metric, window_label,
  period_end, samples, avg, p95, p99, max,
  slope_per_day, forecast_crossing_ts, threshold, details
) VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (workspace_id, forward_network_id, object_type, object_id, metric, window_label, period_end) WHERE deployment_id IS NULL
DO UPDATE SET
  samples = EXCLUDED.samples,
  avg = EXCLUDED.avg,
  p95 = EXCLUDED.p95,
  p99 = EXCLUDED.p99,
  max = EXCLUDED.max,
  slope_per_day = EXCLUDED.slope_per_day,
  forecast_crossing_ts = EXCLUDED.forecast_crossing_ts,
  threshold = EXCLUDED.threshold,
  details = EXCLUDED.details,
  created_at = now()`,
		row.WorkspaceID, row.ForwardNetworkID,
		row.ObjectType, row.ObjectID, row.Metric, row.Window,
		row.PeriodEnd, row.Samples, nullFloatPtr(row.Avg), nullFloatPtr(row.P95), nullFloatPtr(row.P99), nullFloatPtr(row.Max),
		nullFloatPtr(row.SlopePerDay), nullTimePtr(row.ForecastCrossingTS), nullFloatPtr(row.Threshold), detailsBytes,
	)
	return err
}

func nullFloatPtr(v sql.NullFloat64) any {
	if v.Valid {
		return v.Float64
	}
	return nil
}

func nullTimePtr(v sql.NullTime) any {
	if v.Valid {
		return v.Time
	}
	return nil
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func max(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func quantile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	if q <= 0 {
		return cp[0]
	}
	if q >= 1 {
		return cp[len(cp)-1]
	}
	// Linear interpolation between closest ranks.
	pos := q * float64(len(cp)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return cp[lo]
	}
	frac := pos - float64(lo)
	return cp[lo]*(1-frac) + cp[hi]*frac
}

func linregSlope(x, y []float64) (slope float64, ok bool) {
	if len(x) != len(y) || len(x) < 2 {
		return 0, false
	}
	var sx, sy, sxx, sxy float64
	n := float64(len(x))
	for i := range x {
		sx += x[i]
		sy += y[i]
		sxx += x[i] * x[i]
		sxy += x[i] * y[i]
	}
	den := (n*sxx - sx*sx)
	if den == 0 {
		return 0, false
	}
	return (n*sxy - sx*sy) / den, true
}

// Compile-time guard: keep task type stable.
var _ = skyforgecore.TaskTypeCapacityRollup
