package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type CapacityDeviceInventoryRow struct {
	DeviceName   string   `json:"deviceName"`
	TagNames     []string `json:"tagNames,omitempty"`
	GroupNames   []string `json:"groupNames,omitempty"`
	DeviceType   string   `json:"deviceType,omitempty"`
	Vendor       string   `json:"vendor,omitempty"`
	OS           string   `json:"os,omitempty"`
	Model        *string  `json:"model,omitempty"`
	OSVersion    *string  `json:"osVersion,omitempty"`
	LocationName *string  `json:"locationName,omitempty"`
}

type CapacityInterfaceInventoryRow struct {
	DeviceName         string   `json:"deviceName"`
	DeviceLocationName *string  `json:"deviceLocationName,omitempty"`
	DeviceTagNames     []string `json:"deviceTagNames,omitempty"`
	DeviceGroupNames   []string `json:"deviceGroupNames,omitempty"`
	InterfaceName      string   `json:"interfaceName"`
	Description        *string  `json:"description,omitempty"`
	AdminStatus        string   `json:"adminStatus,omitempty"`
	OperStatus         string   `json:"operStatus,omitempty"`
	Layer              string   `json:"layer,omitempty"`
	InterfaceType      string   `json:"interfaceType,omitempty"`
	Mtu                *int     `json:"mtu,omitempty"`
	SpeedMbps          *int     `json:"speedMbps,omitempty"`

	// Link aggregation (LAG / port-channel).
	AggregateID                      *string  `json:"aggregateId,omitempty"`
	AggregationMemberNames           []string `json:"aggregationMemberNames,omitempty"`
	AggregationConfiguredMemberNames []string `json:"aggregationConfiguredMemberNames,omitempty"`
}

type CapacityRouteScaleRow struct {
	DeviceName string `json:"deviceName"`
	Vrf        string `json:"vrf"`
	IPv4Routes int    `json:"ipv4Routes"`
	IPv6Routes int    `json:"ipv6Routes"`
}

type CapacityBgpNeighborRow struct {
	DeviceName         string  `json:"deviceName"`
	Vrf                string  `json:"vrf"`
	NeighborAddress    string  `json:"neighborAddress"`
	PeerDeviceName     *string `json:"peerDeviceName,omitempty"`
	PeerVrf            *string `json:"peerVrf,omitempty"`
	PeerAs             int64   `json:"peerAs"`
	Enabled            bool    `json:"enabled"`
	SessionState       *string `json:"sessionState,omitempty"`
	ReceivedPrefixes   *int    `json:"receivedPrefixes,omitempty"`
	AdvertisedPrefixes *int    `json:"advertisedPrefixes,omitempty"`
	SessionDurationSec *int64  `json:"sessionDurationSec,omitempty"`
}

type CapacityInterfaceVrfRow struct {
	DeviceName   string  `json:"deviceName"`
	Vrf          string  `json:"vrf"`
	IfaceName    string  `json:"ifaceName"`
	SubIfaceName *string `json:"subIfaceName,omitempty"`
}

type CapacityHardwareTcamRow struct {
	DeviceName  string  `json:"deviceName"`
	Vendor      string  `json:"vendor,omitempty"`
	OS          string  `json:"os,omitempty"`
	Model       *string `json:"model,omitempty"`
	TcamUsed    int     `json:"tcamUsed"`
	TcamTotal   int     `json:"tcamTotal"`
	CommandText string  `json:"commandText,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
}

type capacityCachedNQEResponse struct {
	SnapshotID string          `json:"snapshotId,omitempty"`
	Total      int             `json:"total"`
	Results    json.RawMessage `json:"results"`
}

type DeploymentCapacityInventoryResponse struct {
	OwnerUsername    string `json:"ownerUsername"`
	DeploymentID     string `json:"deploymentId"`
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

// GetUserDeploymentCapacityInventory returns the latest cached NQE results for inventory/routing scale.
func (s *Service) GetUserDeploymentCapacityInventory(ctx context.Context, id, deploymentID string) (*DeploymentCapacityInventoryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	_, _, forwardNetworkID, err := s.requireDeploymentForwardNetwork(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	asOf, snapshotID, devices, ifaces, ifaceVrfs, hwTcam, routes, bgp, err := loadLatestCapacityInventory(ctx, s.db, pc.context.ID, deploymentID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load capacity inventory").Err()
	}

	out := &DeploymentCapacityInventoryResponse{
		OwnerUsername:    pc.context.ID,
		DeploymentID:     deploymentID,
		ForwardNetworkID: forwardNetworkID,
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

func loadLatestCapacityInventory(ctx context.Context, db *sql.DB, ownerID, deploymentID string) (asOf time.Time, snapshotID string, devices []CapacityDeviceInventoryRow, ifaces []CapacityInterfaceInventoryRow, ifaceVrfs []CapacityInterfaceVrfRow, hwTcam []CapacityHardwareTcamRow, routes []CapacityRouteScaleRow, bgp []CapacityBgpNeighborRow, err error) {
	if db == nil {
		return time.Time{}, "", nil, nil, nil, nil, nil, nil, fmt.Errorf("db unavailable")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctxReq, `SELECT DISTINCT ON (query_id) query_id, payload, created_at
	FROM sf_capacity_nqe_cache
	WHERE owner_username=$1 AND deployment_id=$2 AND snapshot_id=''
	ORDER BY query_id, created_at DESC`, ownerID, deploymentID)
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
