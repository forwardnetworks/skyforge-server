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

func createPolicyReportZone(ctx context.Context, db *sql.DB, username, userContextID, actor, forwardNetworkID string, req *PolicyReportCreateZoneRequest) (*PolicyReportZone, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if username == "" || actor == "" || forwardNetworkID == "" || req == nil {
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
		UserContextID:    userContextID,
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
  id, user_id, workspace_id, forward_network_id, name, description, subnets, created_by, created_at, updated_at
)
VALUES ($1,(SELECT id FROM sf_users WHERE username=$8 LIMIT 1),$2,$3,$4,NULLIF($5,''),$6,$7,$9,$10)
`, out.ID, out.UserContextID, out.ForwardNetworkID, out.Name, out.Description, subnetsJSON, out.CreatedBy, username, out.CreatedAt, out.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func listPolicyReportZones(ctx context.Context, db *sql.DB, username, userContextID, forwardNetworkID string) ([]PolicyReportZone, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if username == "" || forwardNetworkID == "" {
		return nil, fmt.Errorf("invalid input")
	}

	rows, err := db.QueryContext(ctx, `
SELECT z.id,
       COALESCE(z.user_id::text, z.workspace_id, ''),
       z.forward_network_id,
       z.name,
       COALESCE(z.description,''),
       z.subnets,
       z.created_by,
       z.created_at,
       z.updated_at
  FROM sf_policy_report_zones z
 WHERE z.forward_network_id=$3
   AND (
     (z.user_id=(SELECT id FROM sf_users WHERE username=$1 LIMIT 1)) OR
     ($2 <> '' AND z.workspace_id=$2)
   )
 ORDER BY created_at ASC
`, username, userContextID, forwardNetworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportZone
	for rows.Next() {
		var z PolicyReportZone
		var desc string
		var subnetsJSON []byte
		if err := rows.Scan(&z.ID, &z.UserContextID, &z.ForwardNetworkID, &z.Name, &desc, &subnetsJSON, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, err
		}
		z.Description = strings.TrimSpace(desc)
		_ = json.Unmarshal(subnetsJSON, &z.Subnets)
		out = append(out, z)
	}
	return out, nil
}

func updatePolicyReportZone(ctx context.Context, db *sql.DB, username, userContextID, forwardNetworkID, zoneID string, req *PolicyReportUpdateZoneRequest) (*PolicyReportZone, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	zoneID = strings.TrimSpace(zoneID)
	if username == "" || forwardNetworkID == "" || zoneID == "" || req == nil {
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
 WHERE id=$7
   AND forward_network_id=$6
   AND (
     (user_id=(SELECT id FROM sf_users WHERE username=$5 LIMIT 1)) OR
     ($8 <> '' AND workspace_id=$8)
   )
 RETURNING created_by, created_at
`, name, strings.TrimSpace(req.Description), subnetsJSON, updated, username, forwardNetworkID, zoneID, userContextID).Scan(&createdBy, &createdAt)
	if err != nil {
		return nil, err
	}
	return &PolicyReportZone{
		ID:               zoneID,
		UserContextID:    userContextID,
		ForwardNetworkID: forwardNetworkID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Subnets:          subnets,
		CreatedBy:        strings.TrimSpace(createdBy),
		CreatedAt:        createdAt.UTC(),
		UpdatedAt:        updated,
	}, nil
}

func deletePolicyReportZone(ctx context.Context, db *sql.DB, username, userContextID, forwardNetworkID, zoneID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	username = strings.ToLower(strings.TrimSpace(username))
	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	zoneID = strings.TrimSpace(zoneID)
	if username == "" || forwardNetworkID == "" || zoneID == "" {
		return fmt.Errorf("invalid input")
	}

	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_zones
 WHERE id=$3
   AND forward_network_id=$2
   AND (
     (user_id=(SELECT id FROM sf_users WHERE username=$1 LIMIT 1)) OR
     ($4 <> '' AND workspace_id=$4)
   )
`, username, forwardNetworkID, zoneID, userContextID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
