package taskengine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.app/internal/capacityassets"
)

type capacityNQEResponse struct {
	SnapshotID string          `json:"snapshotId,omitempty"`
	Total      int             `json:"total"`
	Results    json.RawMessage `json:"results"`
}

func capacityNormalizeNQEResponse(body []byte) (*capacityNQEResponse, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}

	var snapshotID string
	if raw := obj["snapshotId"]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &snapshotID)
		snapshotID = strings.TrimSpace(snapshotID)
	}

	total := 0
	if raw := obj["total"]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &total)
	}
	if total == 0 {
		if raw := obj["totalNumItems"]; len(raw) > 0 {
			_ = json.Unmarshal(raw, &total)
		}
	}

	results := json.RawMessage("[]")
	if raw := obj["results"]; len(raw) > 0 {
		results = raw
	} else if raw := obj["items"]; len(raw) > 0 {
		results = raw
	}

	return &capacityNQEResponse{SnapshotID: snapshotID, Total: total, Results: results}, nil
}

func capacityRunNQE(ctx context.Context, client *forwardClient, networkID, snapshotID, queryText string) (*capacityNQEResponse, []byte, error) {
	if client == nil {
		return nil, nil, fmt.Errorf("Forward client unavailable")
	}
	networkID = strings.TrimSpace(networkID)
	queryText = strings.TrimSpace(queryText)
	if networkID == "" {
		return nil, nil, fmt.Errorf("network id is required")
	}
	if queryText == "" {
		return nil, nil, fmt.Errorf("nqe query is required")
	}

	q := url.Values{}
	q.Set("networkId", networkID)
	if v := strings.TrimSpace(snapshotID); v != "" {
		q.Set("snapshotId", v)
	}
	payload := map[string]any{"query": queryText}

	resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/nqe", q, payload)
	if err != nil {
		return nil, body, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, body, fmt.Errorf("forward nqe failed: %s", strings.TrimSpace(string(body)))
	}
	out, err := capacityNormalizeNQEResponse(body)
	if err != nil {
		return nil, body, err
	}
	return out, body, nil
}

type capacityDeviceInvRow struct {
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

type capacityIfaceInvRow struct {
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

	AggregateID                      *string  `json:"aggregateId,omitempty"`
	AggregationMemberNames           []string `json:"aggregationMemberNames,omitempty"`
	AggregationConfiguredMemberNames []string `json:"aggregationConfiguredMemberNames,omitempty"`
}

type capacityInventoryEnrichment struct {
	DeviceByName   map[string]capacityDeviceInvRow
	IfaceByKey     map[string]capacityIfaceInvRow // key: deviceName:interfaceName
	IfaceVrfsByKey map[string][]string            // key: deviceName:interfaceName (vrf names)
}

func (e *Engine) refreshCapacityInventoryCache(ctx context.Context, db *sql.DB, client *forwardClient, ownerID string, deploymentID *string, networkID string, log Logger) (*capacityInventoryEnrichment, error) {
	if db == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	if client == nil {
		return nil, fmt.Errorf("Forward client unavailable")
	}
	ownerID = strings.TrimSpace(ownerID)
	networkID = strings.TrimSpace(networkID)
	if ownerID == "" || networkID == "" {
		return nil, fmt.Errorf("invalid identifiers")
	}
	if deploymentID != nil {
		*deploymentID = strings.TrimSpace(*deploymentID)
		if *deploymentID == "" {
			deploymentID = nil
		}
	}

	queryIDs := []string{
		"capacity-devices.nqe",
		"capacity-interfaces.nqe",
		"capacity-interface-vrfs.nqe",
		"capacity-hardware-tcam.nqe",
		"capacity-route-scale.nqe",
		"capacity-bgp-neighbors.nqe",
	}

	enrich := &capacityInventoryEnrichment{
		DeviceByName:   map[string]capacityDeviceInvRow{},
		IfaceByKey:     map[string]capacityIfaceInvRow{},
		IfaceVrfsByKey: map[string][]string{},
	}

	for _, qid := range queryIDs {
		queryText, err := capacityassets.ReadQuery(qid)
		if err != nil {
			if log != nil {
				log.Errorf("capacity nqe read failed (query=%s): %v", qid, err)
			}
			continue
		}

		ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, raw, err := capacityRunNQE(ctxReq, client, networkID, "", queryText)
		cancel()
		if err != nil || resp == nil {
			if log != nil {
				log.Errorf("capacity nqe run failed (query=%s): %v", qid, err)
			}
			continue
		}

		// Store a stable "latest" cache entry (snapshot_id = '') so we don't accumulate rows every run.
		cachePayload, _ := json.Marshal(resp)
		if err := upsertCapacityNQECache(ctx, db, ownerID, deploymentID, networkID, qid, "", cachePayload); err != nil {
			if log != nil {
				log.Errorf("capacity nqe cache upsert failed (query=%s): %v", qid, err)
			}
		}
		// Best-effort: also insert a snapshot-level row so we can diff across snapshots later.
		if sid := strings.TrimSpace(resp.SnapshotID); sid != "" {
			if err := insertCapacityNQECacheSnapshot(ctx, db, ownerID, deploymentID, networkID, qid, sid, cachePayload); err != nil {
				if log != nil {
					log.Errorf("capacity nqe cache snapshot insert failed (query=%s): %v", qid, err)
				}
			}
		}

		// Build enrichment maps for rollup details.
		switch strings.TrimSpace(qid) {
		case "capacity-devices.nqe":
			var rows []capacityDeviceInvRow
			if err := json.Unmarshal(resp.Results, &rows); err != nil {
				continue
			}
			for _, r := range rows {
				name := strings.TrimSpace(r.DeviceName)
				if name == "" {
					continue
				}
				enrich.DeviceByName[name] = r
			}
		case "capacity-interfaces.nqe":
			var rows []capacityIfaceInvRow
			if err := json.Unmarshal(resp.Results, &rows); err != nil {
				continue
			}
			for _, r := range rows {
				dn := strings.TrimSpace(r.DeviceName)
				in := strings.TrimSpace(r.InterfaceName)
				if dn == "" || in == "" {
					continue
				}
				enrich.IfaceByKey[dn+":"+in] = r
			}
		case "capacity-interface-vrfs.nqe":
			// Map interface -> VRF names. This is used to enrich rollups so the UI can join perf to routing context.
			//
			// We expect duplicates (same iface referenced multiple times); we de-dupe per interface key.
			type row struct {
				DeviceName   string  `json:"deviceName"`
				Vrf          string  `json:"vrf"`
				IfaceName    string  `json:"ifaceName"`
				SubIfaceName *string `json:"subIfaceName,omitempty"`
			}
			var rows []row
			if err := json.Unmarshal(resp.Results, &rows); err != nil {
				continue
			}
			for _, r := range rows {
				dn := strings.TrimSpace(r.DeviceName)
				in := strings.TrimSpace(r.IfaceName)
				vrf := strings.TrimSpace(r.Vrf)
				if dn == "" || in == "" || vrf == "" {
					continue
				}
				key := dn + ":" + in
				cur := enrich.IfaceVrfsByKey[key]
				// Small N: linear check is fine.
				found := false
				for _, v := range cur {
					if v == vrf {
						found = true
						break
					}
				}
				if !found {
					enrich.IfaceVrfsByKey[key] = append(cur, vrf)
				}
			}
		default:
			_ = raw // reserved for future derived rollups (routing/BGP scale)
		}
	}
	return enrich, nil
}

func upsertCapacityNQECache(ctx context.Context, db *sql.DB, ownerID string, deploymentID *string, networkID, queryID, snapshotID string, payload []byte) error {
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	ownerID = strings.TrimSpace(ownerID)
	networkID = strings.TrimSpace(networkID)
	queryID = strings.TrimSpace(queryID)
	snapshotID = strings.TrimSpace(snapshotID)
	if ownerID == "" || networkID == "" || queryID == "" {
		return fmt.Errorf("invalid cache key")
	}
	if payload == nil {
		payload = []byte("null")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var depVal any
	if deploymentID != nil && strings.TrimSpace(*deploymentID) != "" {
		depVal = strings.TrimSpace(*deploymentID)
	}

	var err error
	if depVal != nil {
		_, err = db.ExecContext(ctxReq, `INSERT INTO sf_capacity_nqe_cache (
  owner_id, deployment_id, forward_network_id, query_id, snapshot_id, payload
) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (owner_id, deployment_id, query_id, snapshot_id)
DO UPDATE SET
  forward_network_id = EXCLUDED.forward_network_id,
  payload = EXCLUDED.payload,
  created_at = now()`,
			ownerID, depVal, networkID, queryID, snapshotID, payload,
		)
		return err
	}

	// Network-level cache entry (deployment_id IS NULL).
	_, err = db.ExecContext(ctxReq, `INSERT INTO sf_capacity_nqe_cache (
  owner_id, deployment_id, forward_network_id, query_id, snapshot_id, payload
) VALUES ($1,NULL,$2,$3,$4,$5)
ON CONFLICT (owner_id, forward_network_id, query_id, snapshot_id) WHERE deployment_id IS NULL
DO UPDATE SET
  payload = EXCLUDED.payload,
  created_at = now()`,
		ownerID, networkID, queryID, snapshotID, payload,
	)
	return err
}

func insertCapacityNQECacheSnapshot(ctx context.Context, db *sql.DB, ownerID string, deploymentID *string, networkID, queryID, snapshotID string, payload []byte) error {
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	ownerID = strings.TrimSpace(ownerID)
	networkID = strings.TrimSpace(networkID)
	queryID = strings.TrimSpace(queryID)
	snapshotID = strings.TrimSpace(snapshotID)
	if ownerID == "" || networkID == "" || queryID == "" || snapshotID == "" {
		return fmt.Errorf("invalid cache key")
	}
	if payload == nil {
		payload = []byte("null")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var depVal any
	if deploymentID != nil && strings.TrimSpace(*deploymentID) != "" {
		depVal = strings.TrimSpace(*deploymentID)
	}

	if depVal != nil {
		_, err := db.ExecContext(ctxReq, `INSERT INTO sf_capacity_nqe_cache (
  owner_id, deployment_id, forward_network_id, query_id, snapshot_id, payload
) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (owner_id, deployment_id, query_id, snapshot_id)
DO NOTHING`, ownerID, depVal, networkID, queryID, snapshotID, payload)
		return err
	}

	_, err := db.ExecContext(ctxReq, `INSERT INTO sf_capacity_nqe_cache (
  owner_id, deployment_id, forward_network_id, query_id, snapshot_id, payload
) VALUES ($1,NULL,$2,$3,$4,$5)
ON CONFLICT (owner_id, forward_network_id, query_id, snapshot_id) WHERE deployment_id IS NULL
DO NOTHING`, ownerID, networkID, queryID, snapshotID, payload)
	return err
}
