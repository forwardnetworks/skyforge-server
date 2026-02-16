package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type forwardMetricsSnapshotRow struct {
	ID                            int64
	OwnerUsername                 string
	NetworkRef                    string
	ForwardNetworkID              string
	SnapshotID                    string
	CollectedAt                   time.Time
	NumSuccessfulDevices          *int
	NumCollectionFailureDevices   *int
	NumProcessingFailureDevices   *int
	NumSuccessfulEndpoints        *int
	NumCollectionFailureEndpoints *int
	NumProcessingFailureEndpoints *int
	CollectionDurationMs          *int64
	ProcessingDurationMs          *int64
	Source                        string
	RawMetricsJSON                string
}

func insertForwardMetricsSnapshot(ctx context.Context, db *sql.DB, row forwardMetricsSnapshotRow) error {
	if db == nil {
		return sql.ErrConnDone
	}
	if strings.TrimSpace(row.ForwardNetworkID) == "" {
		return errors.New("forward network id is required")
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_forward_metrics_snapshots (
  owner_username,
  owner_username,
  network_ref,
  forward_network_id,
  snapshot_id,
  collected_at,
  num_successful_devices,
  num_collection_failure_devices,
  num_processing_failure_devices,
  num_successful_endpoints,
  num_collection_failure_endpoints,
  num_processing_failure_endpoints,
  collection_duration_ms,
  processing_duration_ms,
  source,
  raw_metrics
) VALUES (
  NULLIF($1,''),
  NULLIF($2,''),
  NULLIF($3,'')::uuid,
  $4,
  NULLIF($5,''),
  $6,
  $7,
  $8,
  $9,
  $10,
  $11,
  $12,
  $13,
  $14,
  $15,
  COALESCE($16::jsonb, '{}'::jsonb)
)
	`,
		"",
		strings.ToLower(strings.TrimSpace(row.OwnerUsername)),
		strings.TrimSpace(row.NetworkRef),
		strings.TrimSpace(row.ForwardNetworkID),
		strings.TrimSpace(row.SnapshotID),
		row.CollectedAt.UTC(),
		row.NumSuccessfulDevices,
		row.NumCollectionFailureDevices,
		row.NumProcessingFailureDevices,
		row.NumSuccessfulEndpoints,
		row.NumCollectionFailureEndpoints,
		row.NumProcessingFailureEndpoints,
		row.CollectionDurationMs,
		row.ProcessingDurationMs,
		strings.TrimSpace(row.Source),
		strings.TrimSpace(row.RawMetricsJSON),
	)
	return err
}

func listForwardMetricsSnapshots(ctx context.Context, db *sql.DB, ownerID, username, networkRef, forwardNetworkID string, limit int) ([]forwardMetricsSnapshotRow, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	ownerID = strings.TrimSpace(ownerID)
	username = strings.ToLower(strings.TrimSpace(username))
	networkRef = strings.TrimSpace(networkRef)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if networkRef == "" && forwardNetworkID == "" {
		return []forwardMetricsSnapshotRow{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := db.QueryContext(ctx, `
SELECT id,
       COALESCE(owner_username,''),
       COALESCE(owner_username,''),
       COALESCE(network_ref::text,''),
       COALESCE(forward_network_id,''),
       COALESCE(snapshot_id,''),
       collected_at,
       num_successful_devices,
       num_collection_failure_devices,
       num_processing_failure_devices,
       num_successful_endpoints,
       num_collection_failure_endpoints,
       num_processing_failure_endpoints,
       collection_duration_ms,
       processing_duration_ms,
       COALESCE(source,''),
       COALESCE(raw_metrics::text,'{}')
  FROM sf_forward_metrics_snapshots
 WHERE ( ($1 <> '' AND network_ref::text = $1) OR ($2 <> '' AND forward_network_id = $2) )
   AND (owner_username = $3 OR owner_username = $4)
 ORDER BY collected_at DESC
 LIMIT $5
`, networkRef, forwardNetworkID, ownerID, username, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]forwardMetricsSnapshotRow, 0, min(64, limit))
	for rows.Next() {
		var r forwardMetricsSnapshotRow
		if err := rows.Scan(
			&r.ID,
			&r.OwnerUsername,
			&r.OwnerUsername,
			&r.NetworkRef,
			&r.ForwardNetworkID,
			&r.SnapshotID,
			&r.CollectedAt,
			&r.NumSuccessfulDevices,
			&r.NumCollectionFailureDevices,
			&r.NumProcessingFailureDevices,
			&r.NumSuccessfulEndpoints,
			&r.NumCollectionFailureEndpoints,
			&r.NumProcessingFailureEndpoints,
			&r.CollectionDurationMs,
			&r.ProcessingDurationMs,
			&r.Source,
			&r.RawMetricsJSON,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func latestForwardMetricsSnapshot(ctx context.Context, db *sql.DB, ownerID, username, networkRef, forwardNetworkID string) (*forwardMetricsSnapshotRow, error) {
	rows, err := listForwardMetricsSnapshots(ctx, db, ownerID, username, networkRef, forwardNetworkID, 1)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

func parseForwardMetricsJSON(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func maybeIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}

func maybeInt64Ptr(v *int64) *int64 {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}
