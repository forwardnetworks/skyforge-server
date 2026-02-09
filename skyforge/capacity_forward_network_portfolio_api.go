package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ForwardNetworkCapacityPortfolioItem struct {
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`

	AsOf  string `json:"asOf,omitempty"`
	Stale bool   `json:"stale"`

	HotInterfaces   int      `json:"hotInterfaces"`
	SoonestForecast *string  `json:"soonestForecast,omitempty"`
	MaxUtilMax      *float64 `json:"maxUtilMax,omitempty"`
	MaxUtilP95      *float64 `json:"maxUtilP95,omitempty"`
}

type ForwardNetworkCapacityPortfolioResponse struct {
	WorkspaceID string                                `json:"workspaceId"`
	Items       []ForwardNetworkCapacityPortfolioItem `json:"items"`
}

// GetWorkspaceForwardNetworkCapacityPortfolio returns a cross-network capacity summary for a workspace.
//
// Intended as a "portfolio view" across all saved Forward networks (not a NOC alerting page).
//
//encore:api auth method=GET path=/api/workspaces/:id/capacity/forward-networks/portfolio
func (s *Service) GetWorkspaceForwardNetworkCapacityPortfolio(ctx context.Context, id string) (*ForwardNetworkCapacityPortfolioResponse, error) {
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

	// For a workspace portfolio view, include both:
	// - workspace-scoped saved networks (shared with workspace collaborators)
	// - user-scoped saved networks (owned by the current user)
	//
	// Dedup by Forward network id (workspace-scoped wins).
	wsNets, err := listPolicyReportForwardNetworks(ctx, s.db, pc.workspace.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load networks").Err()
	}
	userNets, err := listUserPolicyReportForwardNetworks(ctx, s.db, pc.claims.Username)
	if err != nil && !isMissingDBRelation(err) {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load networks").Err()
	}

	seen := map[string]bool{}
	nets := make([]PolicyReportForwardNetwork, 0, len(wsNets)+len(userNets))
	for _, n := range wsNets {
		fid := strings.TrimSpace(n.ForwardNetwork)
		if fid == "" || seen[fid] {
			continue
		}
		seen[fid] = true
		nets = append(nets, n)
	}
	for _, n := range userNets {
		fid := strings.TrimSpace(n.ForwardNetwork)
		if fid == "" || seen[fid] {
			continue
		}
		seen[fid] = true
		nets = append(nets, n)
	}

	items := make([]ForwardNetworkCapacityPortfolioItem, 0, len(nets))
	for _, n := range nets {
		asOf, hot, soonest, maxMax, maxP95, err := loadForwardNetworkPortfolioStats(ctx, s.db, pc.workspace.ID, n.ForwardNetwork)
		if err != nil {
			// Best-effort.
			asOf = time.Time{}
			hot = 0
			soonest = ""
			maxMax = nil
			maxP95 = nil
		}
		stale := true
		asOfStr := ""
		if !asOf.IsZero() {
			asOfStr = asOf.UTC().Format(time.RFC3339)
			stale = time.Since(asOf) > 2*time.Hour
		}
		var soonestPtr *string
		if strings.TrimSpace(soonest) != "" {
			s := strings.TrimSpace(soonest)
			soonestPtr = &s
		}
		items = append(items, ForwardNetworkCapacityPortfolioItem{
			NetworkRef:       n.ID,
			ForwardNetworkID: n.ForwardNetwork,
			Name:             n.Name,
			Description:      strings.TrimSpace(n.Description),
			AsOf:             asOfStr,
			Stale:            stale,
			HotInterfaces:    hot,
			SoonestForecast:  soonestPtr,
			MaxUtilMax:       maxMax,
			MaxUtilP95:       maxP95,
		})
	}

	return &ForwardNetworkCapacityPortfolioResponse{
		WorkspaceID: pc.workspace.ID,
		Items:       items,
	}, nil
}

func loadForwardNetworkPortfolioStats(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID string) (asOf time.Time, hot int, soonestForecast string, maxUtilMax *float64, maxUtilP95 *float64, err error) {
	if db == nil {
		return time.Time{}, 0, "", nil, nil, fmt.Errorf("db unavailable")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || forwardNetworkID == "" {
		return time.Time{}, 0, "", nil, nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL`, workspaceID, forwardNetworkID).Scan(&asOf); err != nil {
		return time.Time{}, 0, "", nil, nil, err
	}
	if asOf.IsZero() || asOf.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, 0, "", nil, nil, nil
	}

	rows, err := db.QueryContext(ctxReq, `SELECT metric, window_label, max, p95, forecast_crossing_ts
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND period_end=$3
  AND object_type='interface' AND metric IN ('util_ingress','util_egress') AND window_label='7d'`,
		workspaceID, forwardNetworkID, asOf,
	)
	if err != nil {
		return asOf, 0, "", nil, nil, err
	}
	defer rows.Close()

	maxMax := -1.0
	maxP95v := -1.0
	soonest := time.Time{}
	for rows.Next() {
		var metric, window string
		var maxVal, p95Val sql.NullFloat64
		var forecast sql.NullTime
		if err := rows.Scan(&metric, &window, &maxVal, &p95Val, &forecast); err != nil {
			continue
		}
		if maxVal.Valid {
			if maxVal.Float64 >= 0.85 {
				hot++
			}
			if maxVal.Float64 > maxMax {
				maxMax = maxVal.Float64
			}
		}
		if p95Val.Valid && p95Val.Float64 > maxP95v {
			maxP95v = p95Val.Float64
		}
		if forecast.Valid {
			if soonest.IsZero() || forecast.Time.Before(soonest) {
				soonest = forecast.Time
			}
		}
	}
	if maxMax >= 0 {
		v := maxMax
		maxUtilMax = &v
	}
	if maxP95v >= 0 {
		v := maxP95v
		maxUtilP95 = &v
	}
	if !soonest.IsZero() {
		soonestForecast = soonest.UTC().Format(time.RFC3339)
	}
	return asOf, hot, soonestForecast, maxUtilMax, maxUtilP95, nil
}
