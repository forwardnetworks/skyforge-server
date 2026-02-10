package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func createPolicyReportZone(ctx context.Context, db *sql.DB, workspaceID, actor, forwardNetworkID string, req *PolicyReportCreateZoneRequest) (*PolicyReportZone, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || actor == "" || forwardNetworkID == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	subnets := make([]string, 0, len(req.Subnets))
	for _, s := range req.Subnets {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		subnets = append(subnets, s)
	}
	if len(subnets) == 0 {
		return nil, fmt.Errorf("subnets is required")
	}
	subnetsJSON, _ := json.Marshal(subnets)

	now := time.Now().UTC()
	id := uuid.New()
	out := &PolicyReportZone{
		ID:               id.String(),
		WorkspaceID:      workspaceID,
		ForwardNetworkID: forwardNetworkID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Subnets:          subnets,
		CreatedBy:        actor,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	_, err := db.ExecContext(ctx, `
INSERT INTO sf_policy_report_zones(
  id, workspace_id, forward_network_id, name, description, subnets, created_by, created_at, updated_at
)
VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9)
`, out.ID, out.WorkspaceID, out.ForwardNetworkID, out.Name, out.Description, subnetsJSON, out.CreatedBy, out.CreatedAt, out.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func listPolicyReportZones(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID string) ([]PolicyReportZone, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || forwardNetworkID == "" {
		return nil, fmt.Errorf("invalid input")
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, workspace_id, forward_network_id, name, COALESCE(description,''), subnets, created_by, created_at, updated_at
  FROM sf_policy_report_zones
 WHERE workspace_id=$1 AND forward_network_id=$2
 ORDER BY created_at ASC
`, workspaceID, forwardNetworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportZone
	for rows.Next() {
		var z PolicyReportZone
		var desc string
		var subnetsJSON []byte
		if err := rows.Scan(&z.ID, &z.WorkspaceID, &z.ForwardNetworkID, &z.Name, &desc, &subnetsJSON, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, err
		}
		z.Description = strings.TrimSpace(desc)
		_ = json.Unmarshal(subnetsJSON, &z.Subnets)
		out = append(out, z)
	}
	return out, nil
}

func updatePolicyReportZone(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, zoneID string, req *PolicyReportUpdateZoneRequest) (*PolicyReportZone, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	zoneID = strings.TrimSpace(zoneID)
	if workspaceID == "" || forwardNetworkID == "" || zoneID == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	subnets := make([]string, 0, len(req.Subnets))
	for _, s := range req.Subnets {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		subnets = append(subnets, s)
	}
	if len(subnets) == 0 {
		return nil, fmt.Errorf("subnets is required")
	}
	subnetsJSON, _ := json.Marshal(subnets)

	updated := time.Now().UTC()

	var createdBy string
	var createdAt time.Time
	err := db.QueryRowContext(ctx, `
UPDATE sf_policy_report_zones
   SET name=$1,
       description=NULLIF($2,''),
       subnets=$3,
       updated_at=$4
 WHERE workspace_id=$5 AND forward_network_id=$6 AND id=$7
 RETURNING created_by, created_at
`, name, strings.TrimSpace(req.Description), subnetsJSON, updated, workspaceID, forwardNetworkID, zoneID).Scan(&createdBy, &createdAt)
	if err != nil {
		return nil, err
	}
	return &PolicyReportZone{
		ID:               zoneID,
		WorkspaceID:      workspaceID,
		ForwardNetworkID: forwardNetworkID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Subnets:          subnets,
		CreatedBy:        strings.TrimSpace(createdBy),
		CreatedAt:        createdAt.UTC(),
		UpdatedAt:        updated,
	}, nil
}

func deletePolicyReportZone(ctx context.Context, db *sql.DB, workspaceID, forwardNetworkID, zoneID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	zoneID = strings.TrimSpace(zoneID)
	if workspaceID == "" || forwardNetworkID == "" || zoneID == "" {
		return fmt.Errorf("invalid input")
	}

	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_zones
 WHERE workspace_id=$1 AND forward_network_id=$2 AND id=$3
`, workspaceID, forwardNetworkID, zoneID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
