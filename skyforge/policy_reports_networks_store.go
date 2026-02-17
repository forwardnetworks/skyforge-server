package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func createPolicyReportForwardNetwork(ctx context.Context, db *sql.DB, userContextID string, actor string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	if userContextID == "" || actor == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}

	forwardID := strings.TrimSpace(req.ForwardNetwork)
	if forwardID == "" {
		return nil, fmt.Errorf("forwardNetworkId is required")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	desc := strings.TrimSpace(req.Description)
	collectorConfigID := strings.TrimSpace(req.CollectorConfigID)

	id := uuid.New().String()
	policyReportsEnsureUser(ctx, db, actor)

	_, err := db.ExecContext(ctx, `
INSERT INTO sf_policy_report_forward_networks (
  id, workspace_id, forward_network_id, name, description, collector_config_id, created_by
) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7)
`, id, userContextID, forwardID, name, desc, collectorConfigID, actor)
	if err != nil {
		return nil, err
	}

	out := &PolicyReportForwardNetwork{
		ID:                id,
		UserContextID:     userContextID,
		ForwardNetwork:    forwardID,
		Name:              name,
		Description:       desc,
		CollectorConfigID: collectorConfigID,
		CreatedBy:         actor,
	}
	_ = db.QueryRowContext(ctx, `SELECT created_at, updated_at FROM sf_policy_report_forward_networks WHERE id=$1`, id).Scan(&out.CreatedAt, &out.UpdatedAt)
	return out, nil
}

// upsertUserPolicyReportForwardNetwork ensures the current user has a saved network record
// for the given Forward network id (not tied to a user context).
func upsertUserPolicyReportForwardNetwork(ctx context.Context, db *sql.DB, ownerUsername string, actor string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerUsername = strings.ToLower(strings.TrimSpace(ownerUsername))
	actor = strings.ToLower(strings.TrimSpace(actor))
	if ownerUsername == "" || actor == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}

	forwardID := strings.TrimSpace(req.ForwardNetwork)
	if forwardID == "" {
		return nil, fmt.Errorf("forwardNetworkId is required")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	desc := strings.TrimSpace(req.Description)
	collectorConfigID := strings.TrimSpace(req.CollectorConfigID)

	policyReportsEnsureUser(ctx, db, actor)

	var (
		id        string
		createdAt time.Time
		updatedAt time.Time
	)
	err := db.QueryRowContext(ctx, `
INSERT INTO sf_policy_report_forward_networks (
  id, workspace_id, owner_username, forward_network_id, name, description, collector_config_id, created_by
)
VALUES ($1,NULL,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7)
ON CONFLICT (owner_username, forward_network_id) WHERE owner_username IS NOT NULL
DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  collector_config_id = EXCLUDED.collector_config_id,
  updated_at = now()
WHERE sf_policy_report_forward_networks.name IS DISTINCT FROM EXCLUDED.name
   OR sf_policy_report_forward_networks.description IS DISTINCT FROM EXCLUDED.description
   OR sf_policy_report_forward_networks.collector_config_id IS DISTINCT FROM EXCLUDED.collector_config_id
RETURNING id::text, created_at, updated_at
`, uuid.New().String(), ownerUsername, forwardID, name, desc, collectorConfigID, actor).Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}

	return &PolicyReportForwardNetwork{
		ID:                strings.TrimSpace(id),
		UserContextID:     "",
		ForwardNetwork:    forwardID,
		Name:              name,
		Description:       desc,
		CollectorConfigID: collectorConfigID,
		CreatedBy:         actor,
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
	}, nil
}

func listPolicyReportForwardNetworks(ctx context.Context, db *sql.DB, userContextID string) ([]PolicyReportForwardNetwork, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	if userContextID == "" {
		return nil, fmt.Errorf("userContextId required")
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, workspace_id, forward_network_id, name, COALESCE(description,''), COALESCE(collector_config_id,''), created_by, created_at, updated_at
  FROM sf_policy_report_forward_networks
 WHERE workspace_id=$1
 ORDER BY created_at DESC`, userContextID)
	if err != nil {
		if isMissingDBRelation(err) {
			return []PolicyReportForwardNetwork{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportForwardNetwork
	for rows.Next() {
		var n PolicyReportForwardNetwork
		var desc string
		var collectorConfigID string
		if err := rows.Scan(&n.ID, &n.UserContextID, &n.ForwardNetwork, &n.Name, &desc, &collectorConfigID, &n.CreatedBy, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		n.Description = strings.TrimSpace(desc)
		n.CollectorConfigID = strings.TrimSpace(collectorConfigID)
		out = append(out, n)
	}
	return out, nil
}

func listUserPolicyReportForwardNetworks(ctx context.Context, db *sql.DB, ownerUsername string) ([]PolicyReportForwardNetwork, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerUsername = strings.ToLower(strings.TrimSpace(ownerUsername))
	if ownerUsername == "" {
		return nil, fmt.Errorf("owner username required")
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, COALESCE(workspace_id,''), forward_network_id, name, COALESCE(description,''), COALESCE(collector_config_id,''), created_by, created_at, updated_at
  FROM sf_policy_report_forward_networks
 WHERE owner_username=$1
 ORDER BY created_at DESC`, ownerUsername)
	if err != nil {
		if isMissingDBRelation(err) {
			return []PolicyReportForwardNetwork{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportForwardNetwork
	for rows.Next() {
		var n PolicyReportForwardNetwork
		var desc string
		var collectorConfigID string
		if err := rows.Scan(&n.ID, &n.UserContextID, &n.ForwardNetwork, &n.Name, &desc, &collectorConfigID, &n.CreatedBy, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		n.Description = strings.TrimSpace(desc)
		n.CollectorConfigID = strings.TrimSpace(collectorConfigID)
		out = append(out, n)
	}
	return out, nil
}

func deletePolicyReportForwardNetwork(ctx context.Context, db *sql.DB, userContextID string, forwardNetworkRef string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkRef = strings.TrimSpace(forwardNetworkRef)
	if userContextID == "" || forwardNetworkRef == "" {
		return fmt.Errorf("invalid input")
	}

	// Support deleting by uuid id (preferred) or by the Forward network id value.
	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_forward_networks
 WHERE workspace_id=$1 AND (id::text=$2 OR forward_network_id=$2)
`, userContextID, forwardNetworkRef)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func deleteUserPolicyReportForwardNetwork(ctx context.Context, db *sql.DB, ownerUsername string, forwardNetworkRef string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerUsername = strings.ToLower(strings.TrimSpace(ownerUsername))
	forwardNetworkRef = strings.TrimSpace(forwardNetworkRef)
	if ownerUsername == "" || forwardNetworkRef == "" {
		return fmt.Errorf("invalid input")
	}

	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_forward_networks
 WHERE owner_username=$1 AND (id::text=$2 OR forward_network_id=$2)
`, ownerUsername, forwardNetworkRef)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
