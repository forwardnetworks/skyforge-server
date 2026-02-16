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

func policyReportsEnsureUser(ctx context.Context, db *sql.DB, username string) {
	if db == nil {
		return
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return
	}
	ensureAuditActor(ctx, db, username)
}

func createPolicyReportRecertCampaign(ctx context.Context, db *sql.DB, ownerID string, actor string, req *PolicyReportCreateRecertCampaignRequest) (*PolicyReportRecertCampaign, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ownerID = strings.TrimSpace(ownerID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	if ownerID == "" || actor == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	networkID := strings.TrimSpace(req.ForwardNetwork)
	if networkID == "" {
		return nil, fmt.Errorf("forwardNetworkId is required")
	}
	packID := strings.TrimSpace(req.PackID)
	if packID == "" {
		return nil, fmt.Errorf("packId is required")
	}
	desc := strings.TrimSpace(req.Description)
	snapshotID := strings.TrimSpace(req.SnapshotID)

	var dueAt *time.Time
	if strings.TrimSpace(req.DueAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(req.DueAt))
		if err != nil {
			return nil, fmt.Errorf("invalid dueAt (expected RFC3339)")
		}
		t = t.UTC()
		dueAt = &t
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	id := uuid.New().String()
	policyReportsEnsureUser(ctx, db, actor)

	_, err := db.ExecContext(ctx, `
INSERT INTO sf_policy_report_recert_campaigns (
  id, owner_username, name, description, forward_network_id, snapshot_id, pack_id, status, due_at, created_by
) VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,'OPEN',$8,$9)
`, id, ownerID, name, desc, networkID, snapshotID, packID, dueAt, actor)
	if err != nil {
		return nil, err
	}

	out := &PolicyReportRecertCampaign{
		ID:             id,
		OwnerUsername:  ownerID,
		Name:           name,
		Description:    desc,
		ForwardNetwork: networkID,
		SnapshotID:     snapshotID,
		PackID:         packID,
		Status:         "OPEN",
		DueAt:          dueAt,
		CreatedBy:      actor,
	}
	// Load timestamps (server is source of truth).
	_ = db.QueryRowContext(ctx, `SELECT created_at, updated_at FROM sf_policy_report_recert_campaigns WHERE id=$1`, id).Scan(&out.CreatedAt, &out.UpdatedAt)
	return out, nil
}

func listPolicyReportRecertCampaigns(ctx context.Context, db *sql.DB, ownerID string, req *PolicyReportListRecertCampaignsRequest) ([]PolicyReportRecertCampaignWithCounts, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, fmt.Errorf("owner username required")
	}
	status := ""
	limit := 50
	if req != nil {
		status = strings.ToUpper(strings.TrimSpace(req.Status))
		if req.Limit > 0 && req.Limit <= 200 {
			limit = req.Limit
		}
	}

	query := `
SELECT c.id, c.owner_username, c.name, COALESCE(c.description,''), c.forward_network_id, COALESCE(c.snapshot_id,''),
       c.pack_id, c.status, c.due_at, c.created_by, c.created_at, c.updated_at
  FROM sf_policy_report_recert_campaigns c
 WHERE c.owner_username=$1`
	args := []any{ownerID}
	if status != "" {
		query += " AND c.status=$2"
		args = append(args, status)
	}
	query += " ORDER BY c.created_at DESC LIMIT $" + fmt.Sprintf("%d", len(args)+1)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMissingDBRelation(err) {
			return []PolicyReportRecertCampaignWithCounts{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportRecertCampaignWithCounts
	for rows.Next() {
		var c PolicyReportRecertCampaign
		var desc string
		var snapshot string
		var due sql.NullTime
		if err := rows.Scan(&c.ID, &c.OwnerUsername, &c.Name, &desc, &c.ForwardNetwork, &snapshot, &c.PackID, &c.Status, &due, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Description = strings.TrimSpace(desc)
		c.SnapshotID = strings.TrimSpace(snapshot)
		if due.Valid {
			t := due.Time.UTC()
			c.DueAt = &t
		}

		counts := PolicyReportRecertCampaignCounts{}
		_ = db.QueryRowContext(ctx, `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE status='PENDING')::int,
       COUNT(*) FILTER (WHERE status='ATTESTED')::int,
       COUNT(*) FILTER (WHERE status='WAIVED')::int
  FROM sf_policy_report_recert_assignments WHERE campaign_id=$1`, c.ID).Scan(&counts.Total, &counts.Pending, &counts.Attested, &counts.Waived)

		out = append(out, PolicyReportRecertCampaignWithCounts{Campaign: c, Counts: counts})
	}
	return out, nil
}

func getPolicyReportRecertCampaign(ctx context.Context, db *sql.DB, ownerID string, campaignID string) (*PolicyReportRecertCampaignWithCounts, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	campaignID = strings.TrimSpace(campaignID)
	if ownerID == "" || campaignID == "" {
		return nil, fmt.Errorf("invalid input")
	}

	var c PolicyReportRecertCampaign
	var desc string
	var snapshot string
	var due sql.NullTime
	err := db.QueryRowContext(ctx, `
SELECT id, owner_username, name, COALESCE(description,''), forward_network_id, COALESCE(snapshot_id,''),
       pack_id, status, due_at, created_by, created_at, updated_at
  FROM sf_policy_report_recert_campaigns
 WHERE id=$1 AND owner_username=$2`, campaignID, ownerID).Scan(
		&c.ID, &c.OwnerUsername, &c.Name, &desc, &c.ForwardNetwork, &snapshot,
		&c.PackID, &c.Status, &due, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.Description = strings.TrimSpace(desc)
	c.SnapshotID = strings.TrimSpace(snapshot)
	if due.Valid {
		t := due.Time.UTC()
		c.DueAt = &t
	}

	counts := PolicyReportRecertCampaignCounts{}
	_ = db.QueryRowContext(ctx, `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE status='PENDING')::int,
       COUNT(*) FILTER (WHERE status='ATTESTED')::int,
       COUNT(*) FILTER (WHERE status='WAIVED')::int
  FROM sf_policy_report_recert_assignments WHERE campaign_id=$1`, c.ID).Scan(&counts.Total, &counts.Pending, &counts.Attested, &counts.Waived)

	return &PolicyReportRecertCampaignWithCounts{Campaign: c, Counts: counts}, nil
}

func replacePolicyReportRecertAssignments(ctx context.Context, db *sql.DB, ownerID string, campaignID string, assignee string, findings []PolicyReportRecertAssignment) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	campaignID = strings.TrimSpace(campaignID)
	assignee = strings.ToLower(strings.TrimSpace(assignee))
	if ownerID == "" || campaignID == "" {
		return 0, fmt.Errorf("invalid input")
	}
	if assignee != "" {
		policyReportsEnsureUser(ctx, db, assignee)
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM sf_policy_report_recert_assignments WHERE campaign_id=$1`, campaignID); err != nil {
		return 0, err
	}

	created := 0
	for _, a := range findings {
		id := uuid.New().String()
		findingID := strings.TrimSpace(a.FindingID)
		checkID := strings.TrimSpace(a.CheckID)
		if findingID == "" || checkID == "" {
			continue
		}
		finding := a.Finding
		if len(finding) == 0 {
			finding = json.RawMessage(`{}`)
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO sf_policy_report_recert_assignments (
  id, campaign_id, owner_username, finding_id, check_id, assignee_username, status, finding
) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),'PENDING',$7)
`, id, campaignID, ownerID, findingID, checkID, assignee, finding)
		if err != nil {
			return 0, err
		}
		created++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return created, nil
}

func listPolicyReportRecertAssignments(ctx context.Context, db *sql.DB, ownerID string, req *PolicyReportListRecertAssignmentsRequest) ([]PolicyReportRecertAssignment, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, fmt.Errorf("owner username required")
	}
	campaignID := ""
	status := ""
	assignee := ""
	limit := 100
	if req != nil {
		campaignID = strings.TrimSpace(req.CampaignID)
		status = strings.ToUpper(strings.TrimSpace(req.Status))
		assignee = strings.ToLower(strings.TrimSpace(req.Assignee))
		if req.Limit > 0 && req.Limit <= 500 {
			limit = req.Limit
		}
	}

	query := `
SELECT id, campaign_id, owner_username, finding_id, check_id, COALESCE(assignee_username,''), status,
       COALESCE(justification,''), attested_at, finding, created_at, updated_at
  FROM sf_policy_report_recert_assignments
 WHERE owner_username=$1`
	args := []any{ownerID}
	i := 2
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id=$%d", i)
		args = append(args, campaignID)
		i++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, status)
		i++
	}
	if assignee != "" {
		query += fmt.Sprintf(" AND assignee_username=$%d", i)
		args = append(args, assignee)
		i++
	}
	query += " ORDER BY updated_at DESC LIMIT $" + fmt.Sprintf("%d", i)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMissingDBRelation(err) {
			return []PolicyReportRecertAssignment{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportRecertAssignment
	for rows.Next() {
		var a PolicyReportRecertAssignment
		var assignee string
		var just string
		var att sql.NullTime
		if err := rows.Scan(&a.ID, &a.CampaignID, &a.OwnerUsername, &a.FindingID, &a.CheckID, &assignee, &a.Status, &just, &att, &a.Finding, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		a.Assignee = strings.TrimSpace(assignee)
		a.Justification = strings.TrimSpace(just)
		if att.Valid {
			t := att.Time.UTC()
			a.AttestedAt = &t
		}

		// Pull common check metadata and risk score if we can parse the finding blob.
		meta := policyReportsLookupCheckMeta(a.CheckID)
		a.CheckTitle = meta.Title
		a.CheckCategory = meta.Category
		a.CheckSeverity = meta.Severity
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(a.Finding, &obj); err == nil && obj != nil {
			score, reasons := policyReportsComputeRisk(meta, obj)
			a.FindingRisk = score
			a.FindingReasons = reasons
			// Quick "asset key" for sorting in UI.
			if v := policyReportsGetString(obj, "device"); v != "" {
				a.FindingAssetKey = v
			} else if v := policyReportsGetString(obj, "securityGroupId"); v != "" {
				a.FindingAssetKey = v
			} else if v := policyReportsGetString(obj, "securityGroup"); v != "" {
				a.FindingAssetKey = v
			}
		}

		out = append(out, a)
	}
	return out, nil
}

func updatePolicyReportAssignmentStatus(ctx context.Context, db *sql.DB, ownerID string, assignmentID string, newStatus string, justification string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	assignmentID = strings.TrimSpace(assignmentID)
	newStatus = strings.ToUpper(strings.TrimSpace(newStatus))
	justification = strings.TrimSpace(justification)
	if ownerID == "" || assignmentID == "" {
		return fmt.Errorf("invalid input")
	}
	if newStatus != "ATTESTED" && newStatus != "WAIVED" {
		return fmt.Errorf("invalid status")
	}

	_, err := db.ExecContext(ctx, `
UPDATE sf_policy_report_recert_assignments
   SET status=$1,
       justification=NULLIF($2,''),
       attested_at=now(),
       updated_at=now()
 WHERE id=$3 AND owner_username=$4
`, newStatus, justification, assignmentID, ownerID)
	return err
}

func createPolicyReportException(ctx context.Context, db *sql.DB, ownerID string, actor string, req *PolicyReportCreateExceptionRequest) (*PolicyReportException, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	if ownerID == "" || actor == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}
	networkID := strings.TrimSpace(req.ForwardNetwork)
	if networkID == "" {
		return nil, fmt.Errorf("forwardNetworkId is required")
	}
	findingID := strings.TrimSpace(req.FindingID)
	checkID := strings.TrimSpace(req.CheckID)
	just := strings.TrimSpace(req.Justification)
	if findingID == "" || checkID == "" || just == "" {
		return nil, fmt.Errorf("findingId, checkId, and justification are required")
	}
	var expiresAt *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			return nil, fmt.Errorf("invalid expiresAt (expected RFC3339)")
		}
		t = t.UTC()
		expiresAt = &t
	}

	id := uuid.New().String()
	policyReportsEnsureUser(ctx, db, actor)
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_policy_report_exceptions (
  id, owner_username, forward_network_id, finding_id, check_id, status, justification, ticket_url, expires_at, created_by
) VALUES ($1,$2,$3,$4,$5,'PROPOSED',$6,NULLIF($7,''),$8,$9)
`, id, ownerID, networkID, findingID, checkID, just, strings.TrimSpace(req.TicketURL), expiresAt, actor)
	if err != nil {
		return nil, err
	}
	var out PolicyReportException
	out.ID = id
	out.OwnerUsername = ownerID
	out.ForwardNetwork = networkID
	out.FindingID = findingID
	out.CheckID = checkID
	out.Status = "PROPOSED"
	out.Justification = just
	out.TicketURL = strings.TrimSpace(req.TicketURL)
	out.ExpiresAt = expiresAt
	out.CreatedBy = actor
	_ = db.QueryRowContext(ctx, `SELECT created_at, updated_at FROM sf_policy_report_exceptions WHERE id=$1`, id).Scan(&out.CreatedAt, &out.UpdatedAt)
	return &out, nil
}

func listPolicyReportExceptions(ctx context.Context, db *sql.DB, ownerID string, req *PolicyReportListExceptionsRequest) ([]PolicyReportException, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, fmt.Errorf("owner username required")
	}
	networkID := ""
	status := ""
	limit := 100
	if req != nil {
		networkID = strings.TrimSpace(req.ForwardNetwork)
		status = strings.ToUpper(strings.TrimSpace(req.Status))
		if req.Limit > 0 && req.Limit <= 500 {
			limit = req.Limit
		}
	}

	query := `
SELECT id, owner_username, forward_network_id, finding_id, check_id, status, justification, COALESCE(ticket_url,''), expires_at,
       created_by, COALESCE(approved_by,''), created_at, updated_at
  FROM sf_policy_report_exceptions
 WHERE owner_username=$1`
	args := []any{ownerID}
	if networkID != "" {
		query += " AND forward_network_id=$2"
		args = append(args, networkID)
	}
	if status != "" {
		query += " AND status=$" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, status)
	}
	query += " ORDER BY updated_at DESC LIMIT $" + fmt.Sprintf("%d", len(args)+1)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMissingDBRelation(err) {
			return []PolicyReportException{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportException
	for rows.Next() {
		var e PolicyReportException
		var network string
		var ticket string
		var approved string
		var expires sql.NullTime
		if err := rows.Scan(&e.ID, &e.OwnerUsername, &network, &e.FindingID, &e.CheckID, &e.Status, &e.Justification, &ticket, &expires, &e.CreatedBy, &approved, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.ForwardNetwork = strings.TrimSpace(network)
		e.TicketURL = strings.TrimSpace(ticket)
		e.ApprovedBy = strings.TrimSpace(approved)
		if expires.Valid {
			t := expires.Time.UTC()
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	return out, nil
}

func updatePolicyReportExceptionStatus(ctx context.Context, db *sql.DB, ownerID string, exceptionID string, actor string, newStatus string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	exceptionID = strings.TrimSpace(exceptionID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	newStatus = strings.ToUpper(strings.TrimSpace(newStatus))
	if ownerID == "" || exceptionID == "" || actor == "" {
		return fmt.Errorf("invalid input")
	}
	if newStatus != "APPROVED" && newStatus != "REJECTED" {
		return fmt.Errorf("invalid status")
	}
	policyReportsEnsureUser(ctx, db, actor)
	_, err := db.ExecContext(ctx, `
UPDATE sf_policy_report_exceptions
   SET status=$1,
       approved_by=CASE WHEN $1='APPROVED' THEN $2 ELSE approved_by END,
       updated_at=now()
 WHERE id=$3 AND owner_username=$4
`, newStatus, actor, exceptionID, ownerID)
	return err
}

func policyReportAudit(ctx context.Context, db *sql.DB, ownerID string, actor string, action string, details map[string]any) {
	if db == nil {
		return
	}
	ownerID = strings.TrimSpace(ownerID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	action = strings.TrimSpace(action)
	if ownerID == "" || actor == "" || action == "" {
		return
	}
	policyReportsEnsureUser(ctx, db, actor)
	b, _ := json.Marshal(details)
	_, _ = db.ExecContext(ctx, `
INSERT INTO sf_policy_report_audit_log (owner_username, actor_username, action, details)
VALUES ($1,$2,$3,$4)
`, ownerID, actor, action, string(b))
}
