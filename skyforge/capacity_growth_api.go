package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type DeploymentCapacityGrowthQuery struct {
	Metric       string `query:"metric"`
	Window       string `query:"window"`
	ObjectType   string `query:"objectType" encore:"optional"`
	CompareHours int    `query:"compareHours" encore:"optional"`
	Limit        int    `query:"limit" encore:"optional"`
}

type CapacityGrowthRow struct {
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
	Metric     string `json:"metric"`
	Window     string `json:"window"`

	Now  CapacityRollupRow  `json:"now"`
	Prev *CapacityRollupRow `json:"prev,omitempty"`

	DeltaP95     *float64 `json:"deltaP95,omitempty"`
	DeltaMax     *float64 `json:"deltaMax,omitempty"`
	DeltaP95Gbps *float64 `json:"deltaP95Gbps,omitempty"`
}

type DeploymentCapacityGrowthResponse struct {
	UserContextID string              `json:"userContextId"`
	DeploymentID  string              `json:"deploymentId"`
	Metric        string              `json:"metric"`
	Window        string              `json:"window"`
	ObjectType    string              `json:"objectType,omitempty"`
	AsOf          string              `json:"asOf,omitempty"`
	CompareAsOf   string              `json:"compareAsOf,omitempty"`
	CompareHours  int                 `json:"compareHours"`
	Rows          []CapacityGrowthRow `json:"rows"`
}

// GetWorkspaceDeploymentCapacityGrowth compares the latest rollup bucket to an earlier one and returns deltas.
//
// Intended for “top growers” views (week-over-week, day-over-day) without pulling Forward time series.
//
//encore:api auth method=GET path=/api/user-contexts/:id/deployments/:deploymentID/capacity/growth
func (s *Service) GetWorkspaceDeploymentCapacityGrowth(ctx context.Context, id, deploymentID string, q *DeploymentCapacityGrowthQuery) (*DeploymentCapacityGrowthResponse, error) {
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

	_, _, _, err = s.requireDeploymentForwardNetwork(ctx, pc.userContext.ID, deploymentID)
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

	asOf, compareAsOf, rows, err := loadCapacityGrowth(ctx, s.db, pc.userContext.ID, deploymentID, metric, window, objectType, time.Duration(compareHours)*time.Hour)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to compute growth").Err()
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	resp := &DeploymentCapacityGrowthResponse{
		UserContextID: pc.userContext.ID,
		DeploymentID:  deploymentID,
		Metric:        metric,
		Window:        window,
		ObjectType:    objectType,
		CompareHours:  compareHours,
		Rows:          rows,
	}
	if !asOf.IsZero() {
		resp.AsOf = asOf.UTC().Format(time.RFC3339)
	}
	if !compareAsOf.IsZero() {
		resp.CompareAsOf = compareAsOf.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

func loadCapacityGrowth(ctx context.Context, db *sql.DB, userContextID, deploymentID, metric, window, objectType string, compareDur time.Duration) (asOf time.Time, compareAsOf time.Time, out []CapacityGrowthRow, err error) {
	if db == nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("db unavailable")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Latest bucket.
	if err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND deployment_id=$2 AND metric=$3 AND window=$4`,
		userContextID, deploymentID, metric, window).Scan(&asOf); err != nil {
		return time.Time{}, time.Time{}, nil, err
	}
	if asOf.IsZero() || asOf.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, time.Time{}, []CapacityGrowthRow{}, nil
	}

	// Compare bucket: nearest bucket <= (asOf - compareDur).
	target := asOf.Add(-compareDur)
	if err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND deployment_id=$2 AND metric=$3 AND window=$4 AND period_end <= $5`,
		userContextID, deploymentID, metric, window, target).Scan(&compareAsOf); err != nil {
		return asOf, time.Time{}, nil, err
	}
	if compareAsOf.IsZero() || compareAsOf.Equal(time.Unix(0, 0).UTC()) {
		compareAsOf = time.Time{}
	}

	loadBucket := func(ts time.Time) ([]CapacityRollupRow, error) {
		if ts.IsZero() {
			return []CapacityRollupRow{}, nil
		}
		args := []any{userContextID, deploymentID, metric, window, ts}
		query := `SELECT forward_network_id, object_type, object_id, metric, window,
  period_end, samples, avg, p95, p99, max, slope_per_day, forecast_crossing_ts, threshold, details, created_at
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND deployment_id=$2 AND metric=$3 AND window=$4 AND period_end=$5`
		if strings.TrimSpace(objectType) != "" {
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
				UserContextID:    userContextID,
				DeploymentID:     deploymentID,
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
