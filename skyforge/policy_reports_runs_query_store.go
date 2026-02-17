package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func listPolicyReportRuns(ctx context.Context, db *sql.DB, userContextID string, forwardNetworkID string, packID string, status string, limit int) ([]PolicyReportRun, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	packID = strings.TrimSpace(packID)
	status = strings.ToUpper(strings.TrimSpace(status))
	if userContextID == "" {
		return nil, fmt.Errorf("invalid input")
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	query := `
SELECT id, workspace_id, forward_network_id, snapshot_id, pack_id, title, status, COALESCE(error,''), created_by,
       started_at, finished_at, request
  FROM sf_policy_report_runs
 WHERE workspace_id=$1`
	args := []any{userContextID}
	i := 2
	if forwardNetworkID != "" {
		query += fmt.Sprintf(" AND forward_network_id=$%d", i)
		args = append(args, forwardNetworkID)
		i++
	}
	if packID != "" {
		query += fmt.Sprintf(" AND pack_id=$%d", i)
		args = append(args, packID)
		i++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, status)
		i++
	}
	query += " ORDER BY started_at DESC LIMIT $" + fmt.Sprintf("%d", i)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportRun
	for rows.Next() {
		var r PolicyReportRun
		var finished sql.NullTime
		var requestJSON []byte
		if err := rows.Scan(&r.ID, &r.UserContextID, &r.ForwardNetworkID, &r.SnapshotID, &r.PackID, &r.Title, &r.Status, &r.Error, &r.CreatedBy, &r.StartedAt, &finished, &requestJSON); err != nil {
			return nil, err
		}
		r.Title = strings.TrimSpace(r.Title)
		if finished.Valid {
			t := finished.Time.UTC()
			r.FinishedAt = &t
		}
		if len(requestJSON) > 0 {
			r.Request = json.RawMessage(requestJSON)
		}
		out = append(out, r)
	}
	return out, nil
}

func getPolicyReportRun(ctx context.Context, db *sql.DB, userContextID string, runID string) (*PolicyReportRun, []PolicyReportRunCheck, error) {
	if db == nil {
		return nil, nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	runID = strings.TrimSpace(runID)
	if userContextID == "" || runID == "" {
		return nil, nil, fmt.Errorf("invalid input")
	}

	var r PolicyReportRun
	var finished sql.NullTime
	var requestJSON []byte
	err := db.QueryRowContext(ctx, `
SELECT id, workspace_id, forward_network_id, snapshot_id, pack_id, title, status, COALESCE(error,''), created_by,
       started_at, finished_at, request
  FROM sf_policy_report_runs
 WHERE workspace_id=$1 AND id=$2
`, userContextID, runID).Scan(&r.ID, &r.UserContextID, &r.ForwardNetworkID, &r.SnapshotID, &r.PackID, &r.Title, &r.Status, &r.Error, &r.CreatedBy, &r.StartedAt, &finished, &requestJSON)
	if err != nil {
		return nil, nil, err
	}
	r.Title = strings.TrimSpace(r.Title)
	if finished.Valid {
		t := finished.Time.UTC()
		r.FinishedAt = &t
	}
	if len(requestJSON) > 0 {
		r.Request = json.RawMessage(requestJSON)
	}

	rows, err := db.QueryContext(ctx, `
SELECT run_id, check_id, total
  FROM sf_policy_report_run_checks
 WHERE run_id=$1
 ORDER BY check_id ASC
`, runID)
	if err != nil {
		return &r, nil, err
	}
	defer rows.Close()

	var checks []PolicyReportRunCheck
	for rows.Next() {
		var c PolicyReportRunCheck
		if err := rows.Scan(&c.RunID, &c.CheckID, &c.Total); err != nil {
			return &r, nil, err
		}
		checks = append(checks, c)
	}
	return &r, checks, nil
}

func listPolicyReportRunFindings(ctx context.Context, db *sql.DB, userContextID string, runID string, checkID string, limit int) ([]PolicyReportRunFinding, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	runID = strings.TrimSpace(runID)
	checkID = strings.TrimSpace(checkID)
	if userContextID == "" || runID == "" {
		return nil, fmt.Errorf("invalid input")
	}
	if limit <= 0 || limit > 2000 {
		limit = 500
	}

	query := `
SELECT f.run_id, f.check_id, f.finding_id, f.risk_score, COALESCE(f.asset_key,''), f.finding
  FROM sf_policy_report_run_findings f
  JOIN sf_policy_report_runs r ON (r.id=f.run_id)
 WHERE r.workspace_id=$1 AND f.run_id=$2`
	args := []any{userContextID, runID}
	i := 3
	if checkID != "" {
		query += fmt.Sprintf(" AND f.check_id=$%d", i)
		args = append(args, checkID)
		i++
	}
	query += " ORDER BY f.risk_score DESC, f.finding_id ASC LIMIT $" + fmt.Sprintf("%d", i)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportRunFinding
	for rows.Next() {
		var f PolicyReportRunFinding
		var asset string
		var findingJSON []byte
		if err := rows.Scan(&f.RunID, &f.CheckID, &f.FindingID, &f.RiskScore, &asset, &findingJSON); err != nil {
			return nil, err
		}
		f.AssetKey = strings.TrimSpace(asset)
		if len(findingJSON) > 0 {
			f.Finding = json.RawMessage(findingJSON)
		}
		out = append(out, f)
	}
	return out, nil
}

func listPolicyReportFindingsAgg(ctx context.Context, db *sql.DB, userContextID string, forwardNetworkID string, checkID string, status string, limit int) ([]PolicyReportFindingAgg, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	userContextID = strings.TrimSpace(userContextID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	checkID = strings.TrimSpace(checkID)
	status = strings.ToUpper(strings.TrimSpace(status))
	if userContextID == "" {
		return nil, fmt.Errorf("invalid input")
	}
	if limit <= 0 || limit > 2000 {
		limit = 500
	}

	query := `
SELECT workspace_id, forward_network_id, check_id, finding_id, status, risk_score, COALESCE(asset_key,''), finding,
       first_seen_at, last_seen_at, resolved_at, last_run_id
  FROM sf_policy_report_findings_agg
 WHERE workspace_id=$1`
	args := []any{userContextID}
	i := 2
	if forwardNetworkID != "" {
		query += fmt.Sprintf(" AND forward_network_id=$%d", i)
		args = append(args, forwardNetworkID)
		i++
	}
	if checkID != "" {
		query += fmt.Sprintf(" AND check_id=$%d", i)
		args = append(args, checkID)
		i++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, status)
		i++
	}
	query += " ORDER BY risk_score DESC, last_seen_at DESC LIMIT $" + fmt.Sprintf("%d", i)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportFindingAgg
	for rows.Next() {
		var f PolicyReportFindingAgg
		var asset string
		var findingJSON []byte
		var resolved sql.NullTime
		var lastRun sql.NullString
		if err := rows.Scan(&f.UserContextID, &f.ForwardNetworkID, &f.CheckID, &f.FindingID, &f.Status, &f.RiskScore, &asset, &findingJSON, &f.FirstSeenAt, &f.LastSeenAt, &resolved, &lastRun); err != nil {
			return nil, err
		}
		f.AssetKey = strings.TrimSpace(asset)
		if len(findingJSON) > 0 {
			f.Finding = json.RawMessage(findingJSON)
		}
		if resolved.Valid {
			t := resolved.Time.UTC()
			f.ResolvedAt = &t
		}
		if lastRun.Valid {
			f.LastRunID = strings.TrimSpace(lastRun.String)
		}
		out = append(out, f)
	}
	return out, nil
}
