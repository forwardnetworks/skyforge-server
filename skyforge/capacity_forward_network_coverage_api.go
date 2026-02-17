package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ForwardNetworkCapacityCoverageResponse struct {
	UserContextID    string `json:"userContextId"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`

	AsOfRollups   string `json:"asOfRollups,omitempty"`
	AsOfInventory string `json:"asOfInventory,omitempty"`

	DevicesTotal int `json:"devicesTotal"`
	IfacesTotal  int `json:"ifacesTotal"`

	IfacesWithSpeed int `json:"ifacesWithSpeed"`
	IfacesAdminUp   int `json:"ifacesAdminUp"`
	IfacesOperUp    int `json:"ifacesOperUp"`

	RollupsInterfaceTotal int `json:"rollupsInterfaceTotal"`
	RollupsDeviceTotal    int `json:"rollupsDeviceTotal"`
	RollupsWithSamples    int `json:"rollupsWithSamples"`
}

// GetUserContextForwardNetworkCapacityCoverage returns collection coverage / data-quality counters.
//
// This is intentionally lightweight: it's used to build trust in the dashboard and
// to quickly identify missing speed, missing samples, staleness, etc.
func (s *Service) GetUserContextForwardNetworkCapacityCoverage(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacityCoverageResponse, error) {
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

	asOfInv, _, devices, ifaces, _, _, _, _, err := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.claims.Username, pc.userContext.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load inventory").Err()
	}

	ifacesWithSpeed := 0
	ifacesAdminUp := 0
	ifacesOperUp := 0
	for _, r := range ifaces {
		if r.SpeedMbps != nil && *r.SpeedMbps > 0 {
			ifacesWithSpeed++
		}
		if strings.EqualFold(strings.TrimSpace(r.AdminStatus), "UP") {
			ifacesAdminUp++
		}
		if strings.EqualFold(strings.TrimSpace(r.OperStatus), "UP") {
			ifacesOperUp++
		}
	}

	asOfRollups, ifaceRows, devRows, withSamples, err := loadForwardNetworkRollupCoverage(ctx, s.db, pc.userContext.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load rollup coverage").Err()
	}

	out := &ForwardNetworkCapacityCoverageResponse{
		UserContextID:         pc.userContext.ID,
		NetworkRef:            net.ID,
		ForwardNetworkID:      net.ForwardNetworkID,
		DevicesTotal:          len(devices),
		IfacesTotal:           len(ifaces),
		IfacesWithSpeed:       ifacesWithSpeed,
		IfacesAdminUp:         ifacesAdminUp,
		IfacesOperUp:          ifacesOperUp,
		RollupsInterfaceTotal: ifaceRows,
		RollupsDeviceTotal:    devRows,
		RollupsWithSamples:    withSamples,
	}
	if !asOfInv.IsZero() {
		out.AsOfInventory = asOfInv.UTC().Format(time.RFC3339)
	}
	if !asOfRollups.IsZero() {
		out.AsOfRollups = asOfRollups.UTC().Format(time.RFC3339)
	}
	return out, nil
}

func loadForwardNetworkRollupCoverage(ctx context.Context, db *sql.DB, userContextID, forwardNetworkID string) (asOf time.Time, ifaceRows int, devRows int, withSamples int, err error) {
	if db == nil {
		return time.Time{}, 0, 0, 0, fmt.Errorf("db unavailable")
	}
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if userContextID == "" || forwardNetworkID == "" {
		return time.Time{}, 0, 0, 0, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := db.QueryRowContext(ctxReq, `SELECT COALESCE(MAX(period_end), 'epoch'::timestamptz)
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL`, userContextID, forwardNetworkID).Scan(&asOf); err != nil {
		return time.Time{}, 0, 0, 0, err
	}
	if asOf.IsZero() || asOf.Equal(time.Unix(0, 0).UTC()) {
		return time.Time{}, 0, 0, 0, nil
	}

	rows, err := db.QueryContext(ctxReq, `SELECT object_type, samples
FROM sf_capacity_rollups
WHERE workspace_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND period_end=$3`, userContextID, forwardNetworkID, asOf)
	if err != nil {
		return time.Time{}, 0, 0, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var ot string
		var samples int
		if err := rows.Scan(&ot, &samples); err != nil {
			continue
		}
		ot = strings.TrimSpace(ot)
		if ot == "interface" {
			ifaceRows++
		} else if ot == "device" {
			devRows++
		}
		if samples > 0 {
			withSamples++
		}
	}
	return asOf, ifaceRows, devRows, withSamples, nil
}
