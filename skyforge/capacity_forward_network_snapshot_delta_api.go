package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type CapacityDeviceDeltaRow struct {
	DeviceName string                      `json:"deviceName"`
	ChangeType string                      `json:"changeType"` // added|removed|changed
	Changes    []string                    `json:"changes,omitempty"`
	Prev       *CapacityDeviceInventoryRow `json:"prev,omitempty"`
	Now        *CapacityDeviceInventoryRow `json:"now,omitempty"`
}

type CapacityInterfaceDeltaRow struct {
	DeviceName    string                         `json:"deviceName"`
	InterfaceName string                         `json:"interfaceName"`
	ChangeType    string                         `json:"changeType"` // added|removed|changed
	Changes       []string                       `json:"changes,omitempty"`
	Prev          *CapacityInterfaceInventoryRow `json:"prev,omitempty"`
	Now           *CapacityInterfaceInventoryRow `json:"now,omitempty"`
}

type CapacityRouteScaleDeltaRow struct {
	DeviceName string `json:"deviceName"`
	Vrf        string `json:"vrf"`

	IPv4Now   int `json:"ipv4Now"`
	IPv6Now   int `json:"ipv6Now"`
	IPv4Prev  int `json:"ipv4Prev"`
	IPv6Prev  int `json:"ipv6Prev"`
	IPv4Delta int `json:"ipv4Delta"`
	IPv6Delta int `json:"ipv6Delta"`
}

type CapacityBgpNeighborDeltaRow struct {
	DeviceName string `json:"deviceName"`
	Vrf        string `json:"vrf"`

	NeighborsNow   int `json:"neighborsNow"`
	NeighborsPrev  int `json:"neighborsPrev"`
	NeighborsDelta int `json:"neighborsDelta"`

	EstablishedNow   int `json:"establishedNow"`
	EstablishedPrev  int `json:"establishedPrev"`
	EstablishedDelta int `json:"establishedDelta"`
}

type ForwardNetworkCapacitySnapshotDeltaResponse struct {
	WorkspaceID      string `json:"workspaceId"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`

	LatestSnapshotID string `json:"latestSnapshotId,omitempty"`
	PrevSnapshotID   string `json:"prevSnapshotId,omitempty"`

	RouteDelta []CapacityRouteScaleDeltaRow  `json:"routeDelta"`
	BgpDelta   []CapacityBgpNeighborDeltaRow `json:"bgpDelta"`

	// Inventory changes (art-of-the-possible; useful for drift/change reporting).
	DeviceDelta    []CapacityDeviceDeltaRow    `json:"deviceDelta,omitempty"`
	InterfaceDelta []CapacityInterfaceDeltaRow `json:"interfaceDelta,omitempty"`
}

// GetWorkspaceForwardNetworkCapacitySnapshotDelta compares the last two processed snapshot inventories.
//
// This is a lightweight "changes tab" view: route scale + BGP scale deltas, plus basic inventory drift.
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/capacity/snapshot-delta
func (s *Service) GetWorkspaceForwardNetworkCapacitySnapshotDelta(ctx context.Context, id, networkRef string) (*ForwardNetworkCapacitySnapshotDeltaResponse, error) {
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

	latestSID, prevSID, err := loadLatestTwoCapacitySnapshotIDs(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load snapshot ids").Err()
	}

	resp := &ForwardNetworkCapacitySnapshotDeltaResponse{
		WorkspaceID:      pc.workspace.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		LatestSnapshotID: latestSID,
		PrevSnapshotID:   prevSID,
		RouteDelta:       []CapacityRouteScaleDeltaRow{},
		BgpDelta:         []CapacityBgpNeighborDeltaRow{},
		DeviceDelta:      []CapacityDeviceDeltaRow{},
		InterfaceDelta:   []CapacityInterfaceDeltaRow{},
	}
	if strings.TrimSpace(latestSID) == "" || strings.TrimSpace(prevSID) == "" {
		return resp, nil
	}

	latestRoutes, _ := loadCapacityRouteScaleSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, latestSID)
	prevRoutes, _ := loadCapacityRouteScaleSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, prevSID)
	resp.RouteDelta = diffRouteScale(prevRoutes, latestRoutes)

	latestBgp, _ := loadCapacityBgpNeighborsSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, latestSID)
	prevBgp, _ := loadCapacityBgpNeighborsSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, prevSID)
	resp.BgpDelta = diffBgpScale(prevBgp, latestBgp)

	latestDevices, _ := loadCapacityDevicesSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, latestSID)
	prevDevices, _ := loadCapacityDevicesSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, prevSID)
	resp.DeviceDelta = diffDevices(prevDevices, latestDevices)

	latestIfaces, _ := loadCapacityInterfacesSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, latestSID)
	prevIfaces, _ := loadCapacityInterfacesSnapshot(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID, prevSID)
	resp.InterfaceDelta = diffInterfaces(prevIfaces, latestIfaces)

	return resp, nil
}

func loadLatestTwoCapacitySnapshotIDs(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID string) (latestSID string, prevSID string, err error) {
	if db == nil {
		return "", "", fmt.Errorf("db unavailable")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || forwardNetworkID == "" {
		return "", "", fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctxReq, `SELECT snapshot_id, MAX(created_at) AS as_of
FROM sf_capacity_nqe_cache
WHERE workspace_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL
  AND query_id='capacity-route-scale.nqe' AND snapshot_id <> ''
GROUP BY snapshot_id
ORDER BY as_of DESC
LIMIT 2`, workspaceID, forwardNetworkID)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	sids := []string{}
	for rows.Next() {
		var sid string
		var asOf time.Time
		if err := rows.Scan(&sid, &asOf); err != nil {
			continue
		}
		sid = strings.TrimSpace(sid)
		if sid != "" {
			sids = append(sids, sid)
		}
	}
	if len(sids) >= 1 {
		latestSID = sids[0]
	}
	if len(sids) >= 2 {
		prevSID = sids[1]
	}
	return latestSID, prevSID, nil
}

func loadCapacityNQESnapshotPayload(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, queryID, snapshotID string) (payload []byte, err error) {
	if db == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	queryID = strings.TrimSpace(queryID)
	snapshotID = strings.TrimSpace(snapshotID)
	if workspaceID == "" || forwardNetworkID == "" || queryID == "" || snapshotID == "" {
		return nil, fmt.Errorf("invalid identifiers")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var b []byte
	if err := db.QueryRowContext(ctxReq, `SELECT payload
FROM sf_capacity_nqe_cache
WHERE workspace_id=$1 AND forward_network_id=$2 AND deployment_id IS NULL AND query_id=$3 AND snapshot_id=$4
ORDER BY created_at DESC
LIMIT 1`, workspaceID, forwardNetworkID, queryID, snapshotID).Scan(&b); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

func loadCapacityRouteScaleSnapshot(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, snapshotID string) ([]CapacityRouteScaleRow, error) {
	b, err := loadCapacityNQESnapshotPayload(ctx, db, workspaceID, forwardNetworkID, "capacity-route-scale.nqe", snapshotID)
	if err != nil || len(b) == 0 {
		return []CapacityRouteScaleRow{}, err
	}
	var cached capacityCachedNQEResponse
	_ = json.Unmarshal(b, &cached)
	var out []CapacityRouteScaleRow
	_ = json.Unmarshal(cached.Results, &out)
	return out, nil
}

func loadCapacityBgpNeighborsSnapshot(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, snapshotID string) ([]CapacityBgpNeighborRow, error) {
	b, err := loadCapacityNQESnapshotPayload(ctx, db, workspaceID, forwardNetworkID, "capacity-bgp-neighbors.nqe", snapshotID)
	if err != nil || len(b) == 0 {
		return []CapacityBgpNeighborRow{}, err
	}
	var cached capacityCachedNQEResponse
	_ = json.Unmarshal(b, &cached)
	var out []CapacityBgpNeighborRow
	_ = json.Unmarshal(cached.Results, &out)
	return out, nil
}

func loadCapacityDevicesSnapshot(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, snapshotID string) ([]CapacityDeviceInventoryRow, error) {
	b, err := loadCapacityNQESnapshotPayload(ctx, db, workspaceID, forwardNetworkID, "capacity-devices.nqe", snapshotID)
	if err != nil || len(b) == 0 {
		return []CapacityDeviceInventoryRow{}, err
	}
	var cached capacityCachedNQEResponse
	_ = json.Unmarshal(b, &cached)
	var out []CapacityDeviceInventoryRow
	_ = json.Unmarshal(cached.Results, &out)
	return out, nil
}

func loadCapacityInterfacesSnapshot(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, snapshotID string) ([]CapacityInterfaceInventoryRow, error) {
	b, err := loadCapacityNQESnapshotPayload(ctx, db, workspaceID, forwardNetworkID, "capacity-interfaces.nqe", snapshotID)
	if err != nil || len(b) == 0 {
		return []CapacityInterfaceInventoryRow{}, err
	}
	var cached capacityCachedNQEResponse
	_ = json.Unmarshal(b, &cached)
	var out []CapacityInterfaceInventoryRow
	_ = json.Unmarshal(cached.Results, &out)
	return out, nil
}

func diffRouteScale(prev, now []CapacityRouteScaleRow) []CapacityRouteScaleDeltaRow {
	key := func(d, v string) string { return strings.TrimSpace(d) + "|" + strings.TrimSpace(v) }
	mp := map[string]CapacityRouteScaleRow{}
	mn := map[string]CapacityRouteScaleRow{}
	for _, r := range prev {
		mp[key(r.DeviceName, r.Vrf)] = r
	}
	for _, r := range now {
		mn[key(r.DeviceName, r.Vrf)] = r
	}
	keys := map[string]struct{}{}
	for k := range mp {
		keys[k] = struct{}{}
	}
	for k := range mn {
		keys[k] = struct{}{}
	}
	out := make([]CapacityRouteScaleDeltaRow, 0, len(keys))
	for k := range keys {
		p := mp[k]
		n := mn[k]
		row := CapacityRouteScaleDeltaRow{
			DeviceName: strings.TrimSpace(n.DeviceName),
			Vrf:        strings.TrimSpace(n.Vrf),
			IPv4Now:    n.IPv4Routes,
			IPv6Now:    n.IPv6Routes,
			IPv4Prev:   p.IPv4Routes,
			IPv6Prev:   p.IPv6Routes,
			IPv4Delta:  n.IPv4Routes - p.IPv4Routes,
			IPv6Delta:  n.IPv6Routes - p.IPv6Routes,
		}
		if strings.TrimSpace(row.DeviceName) == "" {
			row.DeviceName = strings.TrimSpace(p.DeviceName)
		}
		if strings.TrimSpace(row.Vrf) == "" {
			row.Vrf = strings.TrimSpace(p.Vrf)
		}
		if row.IPv4Delta != 0 || row.IPv6Delta != 0 {
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceName == out[j].DeviceName {
			return out[i].Vrf < out[j].Vrf
		}
		return out[i].DeviceName < out[j].DeviceName
	})
	return out
}

func diffBgpScale(prev, now []CapacityBgpNeighborRow) []CapacityBgpNeighborDeltaRow {
	type agg struct{ nbrs, est int }
	key := func(d, v string) string { return strings.TrimSpace(d) + "|" + strings.TrimSpace(v) }
	aggSnap := func(rows []CapacityBgpNeighborRow) map[string]agg {
		m := map[string]agg{}
		for _, r := range rows {
			k := key(r.DeviceName, r.Vrf)
			a := m[k]
			a.nbrs++
			if strings.EqualFold(strings.TrimSpace(ptrToString(r.SessionState)), "ESTABLISHED") {
				a.est++
			}
			m[k] = a
		}
		return m
	}
	mp := aggSnap(prev)
	mn := aggSnap(now)
	keys := map[string]struct{}{}
	for k := range mp {
		keys[k] = struct{}{}
	}
	for k := range mn {
		keys[k] = struct{}{}
	}
	out := []CapacityBgpNeighborDeltaRow{}
	for k := range keys {
		p := mp[k]
		n := mn[k]
		parts := strings.SplitN(k, "|", 2)
		dev := ""
		vrf := ""
		if len(parts) > 0 {
			dev = parts[0]
		}
		if len(parts) > 1 {
			vrf = parts[1]
		}
		row := CapacityBgpNeighborDeltaRow{
			DeviceName:       dev,
			Vrf:              vrf,
			NeighborsNow:     n.nbrs,
			NeighborsPrev:    p.nbrs,
			NeighborsDelta:   n.nbrs - p.nbrs,
			EstablishedNow:   n.est,
			EstablishedPrev:  p.est,
			EstablishedDelta: n.est - p.est,
		}
		if row.NeighborsDelta != 0 || row.EstablishedDelta != 0 {
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceName == out[j].DeviceName {
			return out[i].Vrf < out[j].Vrf
		}
		return out[i].DeviceName < out[j].DeviceName
	})
	return out
}

func diffDevices(prev, now []CapacityDeviceInventoryRow) []CapacityDeviceDeltaRow {
	mp := map[string]CapacityDeviceInventoryRow{}
	mn := map[string]CapacityDeviceInventoryRow{}
	for _, r := range prev {
		mp[strings.TrimSpace(r.DeviceName)] = r
	}
	for _, r := range now {
		mn[strings.TrimSpace(r.DeviceName)] = r
	}
	keys := map[string]struct{}{}
	for k := range mp {
		if k != "" {
			keys[k] = struct{}{}
		}
	}
	for k := range mn {
		if k != "" {
			keys[k] = struct{}{}
		}
	}
	out := []CapacityDeviceDeltaRow{}
	for k := range keys {
		p, pok := mp[k]
		n, nok := mn[k]
		switch {
		case !pok && nok:
			nc := n
			out = append(out, CapacityDeviceDeltaRow{DeviceName: k, ChangeType: "added", Now: &nc})
		case pok && !nok:
			pc := p
			out = append(out, CapacityDeviceDeltaRow{DeviceName: k, ChangeType: "removed", Prev: &pc})
		default:
			changes := []string{}
			if strings.TrimSpace(p.Vendor) != strings.TrimSpace(n.Vendor) {
				changes = append(changes, fmt.Sprintf("vendor: %s -> %s", strings.TrimSpace(p.Vendor), strings.TrimSpace(n.Vendor)))
			}
			if strings.TrimSpace(p.OS) != strings.TrimSpace(n.OS) {
				changes = append(changes, fmt.Sprintf("os: %s -> %s", strings.TrimSpace(p.OS), strings.TrimSpace(n.OS)))
			}
			if strings.TrimSpace(ptrToString(p.Model)) != strings.TrimSpace(ptrToString(n.Model)) {
				changes = append(changes, fmt.Sprintf("model: %s -> %s", strings.TrimSpace(ptrToString(p.Model)), strings.TrimSpace(ptrToString(n.Model))))
			}
			if strings.TrimSpace(ptrToString(p.OSVersion)) != strings.TrimSpace(ptrToString(n.OSVersion)) {
				changes = append(changes, fmt.Sprintf("osVersion: %s -> %s", strings.TrimSpace(ptrToString(p.OSVersion)), strings.TrimSpace(ptrToString(n.OSVersion))))
			}
			if strings.TrimSpace(ptrToString(p.LocationName)) != strings.TrimSpace(ptrToString(n.LocationName)) {
				changes = append(changes, fmt.Sprintf("location: %s -> %s", strings.TrimSpace(ptrToString(p.LocationName)), strings.TrimSpace(ptrToString(n.LocationName))))
			}
			if len(changes) == 0 {
				continue
			}
			pc := p
			nc := n
			out = append(out, CapacityDeviceDeltaRow{DeviceName: k, ChangeType: "changed", Changes: changes, Prev: &pc, Now: &nc})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChangeType == out[j].ChangeType {
			return out[i].DeviceName < out[j].DeviceName
		}
		// Put changed first, then added, then removed.
		ord := func(s string) int {
			switch s {
			case "changed":
				return 0
			case "added":
				return 1
			case "removed":
				return 2
			default:
				return 3
			}
		}
		return ord(out[i].ChangeType) < ord(out[j].ChangeType)
	})
	return out
}

func diffInterfaces(prev, now []CapacityInterfaceInventoryRow) []CapacityInterfaceDeltaRow {
	key := func(d, i string) string { return strings.TrimSpace(d) + "|" + strings.TrimSpace(i) }
	mp := map[string]CapacityInterfaceInventoryRow{}
	mn := map[string]CapacityInterfaceInventoryRow{}
	for _, r := range prev {
		mp[key(r.DeviceName, r.InterfaceName)] = r
	}
	for _, r := range now {
		mn[key(r.DeviceName, r.InterfaceName)] = r
	}
	keys := map[string]struct{}{}
	for k := range mp {
		keys[k] = struct{}{}
	}
	for k := range mn {
		keys[k] = struct{}{}
	}
	out := []CapacityInterfaceDeltaRow{}
	for k := range keys {
		p, pok := mp[k]
		n, nok := mn[k]
		parts := strings.SplitN(k, "|", 2)
		dev := ""
		ifn := ""
		if len(parts) > 0 {
			dev = parts[0]
		}
		if len(parts) > 1 {
			ifn = parts[1]
		}
		switch {
		case !pok && nok:
			nc := n
			out = append(out, CapacityInterfaceDeltaRow{DeviceName: dev, InterfaceName: ifn, ChangeType: "added", Now: &nc})
		case pok && !nok:
			pc := p
			out = append(out, CapacityInterfaceDeltaRow{DeviceName: dev, InterfaceName: ifn, ChangeType: "removed", Prev: &pc})
		default:
			changes := []string{}
			if strings.TrimSpace(ptrToString(p.Description)) != strings.TrimSpace(ptrToString(n.Description)) {
				changes = append(changes, "description")
			}
			if strings.TrimSpace(p.AdminStatus) != strings.TrimSpace(n.AdminStatus) {
				changes = append(changes, fmt.Sprintf("admin: %s -> %s", strings.TrimSpace(p.AdminStatus), strings.TrimSpace(n.AdminStatus)))
			}
			if strings.TrimSpace(p.OperStatus) != strings.TrimSpace(n.OperStatus) {
				changes = append(changes, fmt.Sprintf("oper: %s -> %s", strings.TrimSpace(p.OperStatus), strings.TrimSpace(n.OperStatus)))
			}
			if strings.TrimSpace(p.InterfaceType) != strings.TrimSpace(n.InterfaceType) {
				changes = append(changes, fmt.Sprintf("type: %s -> %s", strings.TrimSpace(p.InterfaceType), strings.TrimSpace(n.InterfaceType)))
			}
			if (p.SpeedMbps == nil) != (n.SpeedMbps == nil) || (p.SpeedMbps != nil && n.SpeedMbps != nil && *p.SpeedMbps != *n.SpeedMbps) {
				changes = append(changes, fmt.Sprintf("speedMbps: %s -> %s", intPtrToString(p.SpeedMbps), intPtrToString(n.SpeedMbps)))
			}
			if strings.TrimSpace(ptrToString(p.AggregateID)) != strings.TrimSpace(ptrToString(n.AggregateID)) {
				changes = append(changes, fmt.Sprintf("aggregateId: %s -> %s", strings.TrimSpace(ptrToString(p.AggregateID)), strings.TrimSpace(ptrToString(n.AggregateID))))
			}
			if !stringSliceSetEqual(p.AggregationConfiguredMemberNames, n.AggregationConfiguredMemberNames) {
				changes = append(changes, "configuredMembers")
			} else if !stringSliceSetEqual(p.AggregationMemberNames, n.AggregationMemberNames) {
				changes = append(changes, "members")
			}
			if len(changes) == 0 {
				continue
			}
			pc := p
			nc := n
			out = append(out, CapacityInterfaceDeltaRow{DeviceName: dev, InterfaceName: ifn, ChangeType: "changed", Changes: changes, Prev: &pc, Now: &nc})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChangeType == out[j].ChangeType {
			if out[i].DeviceName == out[j].DeviceName {
				return out[i].InterfaceName < out[j].InterfaceName
			}
			return out[i].DeviceName < out[j].DeviceName
		}
		ord := func(s string) int {
			switch s {
			case "changed":
				return 0
			case "added":
				return 1
			case "removed":
				return 2
			default:
				return 3
			}
		}
		return ord(out[i].ChangeType) < ord(out[j].ChangeType)
	})
	return out
}

func ptrToString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func intPtrToString(p *int) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", *p)
}

func stringSliceSetEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	ma := map[string]int{}
	mb := map[string]int{}
	for _, s := range a {
		ma[strings.TrimSpace(s)]++
	}
	for _, s := range b {
		mb[strings.TrimSpace(s)]++
	}
	if len(ma) != len(mb) {
		return false
	}
	for k, va := range ma {
		if vb, ok := mb[k]; !ok || vb != va {
			return false
		}
	}
	return true
}
