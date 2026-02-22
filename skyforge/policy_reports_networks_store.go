package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func createPolicyReportForwardNetwork(ctx context.Context, db *sql.DB, workspaceID string, actor string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	if workspaceID == "" || actor == "" || req == nil {
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
  id, user_id, forward_network_id, name, description, collector_config_id, created_by
) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7)
`, id, workspaceID, forwardID, name, desc, collectorConfigID, actor)
	if err != nil {
		return nil, err
	}

	out := &PolicyReportForwardNetwork{
		ID:             id,
		WorkspaceID:    workspaceID,
		ForwardNetwork: forwardID,
		Name:           name,
		Description:    desc,
		CollectorConfigID: collectorConfigID,
		CreatedBy:      actor,
	}
	_ = db.QueryRowContext(ctx, `SELECT created_at, updated_at FROM sf_policy_report_forward_networks WHERE id=$1`, id).Scan(&out.CreatedAt, &out.UpdatedAt)
	return out, nil
}

func listPolicyReportForwardNetworks(ctx context.Context, db *sql.DB, workspaceID string) ([]PolicyReportForwardNetwork, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id required")
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, user_id, forward_network_id, name, COALESCE(description,''), COALESCE(collector_config_id,''), created_by, created_at, updated_at
  FROM sf_policy_report_forward_networks
 WHERE user_id=$1
 ORDER BY created_at DESC`, workspaceID)
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
		if err := rows.Scan(&n.ID, &n.WorkspaceID, &n.ForwardNetwork, &n.Name, &desc, &collectorConfigID, &n.CreatedBy, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		n.Description = strings.TrimSpace(desc)
		n.CollectorConfigID = strings.TrimSpace(collectorConfigID)
		out = append(out, n)
	}
	return out, nil
}

func deletePolicyReportForwardNetwork(ctx context.Context, db *sql.DB, workspaceID string, forwardNetworkRef string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	workspaceID = strings.TrimSpace(workspaceID)
	forwardNetworkRef = strings.TrimSpace(forwardNetworkRef)
	if workspaceID == "" || forwardNetworkRef == "" {
		return fmt.Errorf("invalid input")
	}

	// Support deleting by uuid id (preferred) or by the Forward network id value.
	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_forward_networks
 WHERE user_id=$1 AND (id::text=$2 OR forward_network_id=$2)
`, workspaceID, forwardNetworkRef)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
