package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type policyReportsViolationFinding struct {
	CheckID   string
	FindingID string
	RiskScore int
	AssetKey  string
	Finding   json.RawMessage
}

type policyReportsResolveSpec struct {
	CanResolve bool

	// Optional: scope resolution for a check to only findings whose JSON includes this suiteKey.
	// This is used by checks like Paths Assurance where multiple suites share a checkId, but
	// resolution must not cross suite boundaries.
	SuiteKey string
}

func policyReportsExtractViolationFindings(checkID string, resp *PolicyReportNQEResponse) ([]policyReportsViolationFinding, error) {
	checkID = strings.TrimSpace(checkID)
	if resp == nil || len(resp.Results) == 0 {
		return []policyReportsViolationFinding{}, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(resp.Results, &arr); err != nil || len(arr) == 0 {
		return []policyReportsViolationFinding{}, nil
	}

	meta := policyReportsLookupCheckMeta(checkID)

	out := make([]policyReportsViolationFinding, 0, len(arr))
	for _, raw := range arr {
		if len(raw) == 0 {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			continue
		}

		// Only treat rows with an explicit boolean "violation" field as findings.
		var violation bool
		if vraw, ok := obj["violation"]; ok && len(vraw) > 0 {
			_ = json.Unmarshal(vraw, &violation)
		} else {
			continue
		}
		if !violation {
			continue
		}

		id := policyReportsGetString(obj, "findingId")
		if id == "" {
			id = policyReportsComputeFindingID(checkID, raw)
		}

		risk, ok := policyReportsGetInt(obj, "riskScore")
		if !ok {
			risk, _ = policyReportsComputeRisk(meta, obj)
		}
		risk = clampInt(risk, 0, 100)

		asset := strings.TrimSpace(policyReportsGetString(obj, "assetKey"))
		if asset == "" {
			if v := policyReportsGetString(obj, "device"); v != "" {
				asset = v
			} else if v := policyReportsGetString(obj, "Device"); v != "" {
				asset = v
			} else if v := policyReportsGetString(obj, "securityGroupId"); v != "" {
				asset = v
			} else if v := policyReportsGetString(obj, "securityGroup"); v != "" {
				asset = v
			} else if v := policyReportsGetString(obj, "rule"); v != "" {
				asset = v
			} else if v := policyReportsGetString(obj, "Rule"); v != "" {
				asset = v
			}
		}

		out = append(out, policyReportsViolationFinding{
			CheckID:   checkID,
			FindingID: id,
			RiskScore: risk,
			AssetKey:  asset,
			Finding:   raw,
		})
	}
	return out, nil
}

func persistPolicyReportRun(ctx context.Context, db *sql.DB, run *PolicyReportRun, checks []PolicyReportRunCheck, findings []PolicyReportRunFinding, resolveChecks map[string]policyReportsResolveSpec) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	if run == nil {
		return fmt.Errorf("run is required")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	finishedAt := time.Now().UTC()
	if run.FinishedAt != nil {
		finishedAt = run.FinishedAt.UTC()
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO sf_policy_report_runs(
  id, workspace_id, forward_network_id, snapshot_id, pack_id, title, status, error,
  created_by, started_at, finished_at, request
)
VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12)
`, run.ID, run.WorkspaceID, run.ForwardNetworkID, strings.TrimSpace(run.SnapshotID), strings.TrimSpace(run.PackID), strings.TrimSpace(run.Title), strings.TrimSpace(run.Status), strings.TrimSpace(run.Error), run.CreatedBy, run.StartedAt, finishedAt, run.Request)
	if err != nil {
		return err
	}

	for _, c := range checks {
		if strings.TrimSpace(c.CheckID) == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO sf_policy_report_run_checks(run_id, check_id, total)
VALUES ($1,$2,$3)
`, run.ID, strings.TrimSpace(c.CheckID), c.Total)
		if err != nil {
			return err
		}
	}

	for _, f := range findings {
		if strings.TrimSpace(f.CheckID) == "" || strings.TrimSpace(f.FindingID) == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO sf_policy_report_run_findings(run_id, check_id, finding_id, risk_score, asset_key, finding)
VALUES ($1,$2,$3,$4,NULLIF($5,''),$6)
`, run.ID, strings.TrimSpace(f.CheckID), strings.TrimSpace(f.FindingID), f.RiskScore, strings.TrimSpace(f.AssetKey), f.Finding)
		if err != nil {
			return err
		}
	}

	// Update aggregate posture. Only include "violation" findings (already filtered by extraction).
	presentByCheck := map[string]map[string]bool{}
	for _, f := range findings {
		cid := strings.TrimSpace(f.CheckID)
		fid := strings.TrimSpace(f.FindingID)
		if cid == "" || fid == "" {
			continue
		}
		m := presentByCheck[cid]
		if m == nil {
			m = map[string]bool{}
			presentByCheck[cid] = m
		}
		m[fid] = true

		_, err := tx.ExecContext(ctx, `
INSERT INTO sf_policy_report_findings_agg(
  workspace_id, forward_network_id, check_id, finding_id,
  status, risk_score, asset_key, finding,
  first_seen_at, last_seen_at, resolved_at, last_run_id, updated_at
)
VALUES ($1,$2,$3,$4,'ACTIVE',$5,NULLIF($6,''),$7,$8,$8,NULL,$9,now())
ON CONFLICT (workspace_id, forward_network_id, check_id, finding_id)
DO UPDATE SET
  status='ACTIVE',
  risk_score=EXCLUDED.risk_score,
  asset_key=EXCLUDED.asset_key,
  finding=EXCLUDED.finding,
  last_seen_at=EXCLUDED.last_seen_at,
  resolved_at=NULL,
  last_run_id=EXCLUDED.last_run_id,
  updated_at=now()
`, run.WorkspaceID, run.ForwardNetworkID, cid, fid, f.RiskScore, strings.TrimSpace(f.AssetKey), f.Finding, finishedAt, run.ID)
		if err != nil {
			return err
		}
	}

	if err := policyReportsResolveAgg(ctx, tx, run, finishedAt, presentByCheck, resolveChecks); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func policyReportsResolveAgg(ctx context.Context, tx *sql.Tx, run *PolicyReportRun, finishedAt time.Time, presentByCheck map[string]map[string]bool, resolveChecks map[string]policyReportsResolveSpec) error {
	if tx == nil || run == nil {
		return fmt.Errorf("invalid input")
	}

	// Mark resolved for checks where we are confident we saw the full set (no truncation).
	for checkID, spec := range resolveChecks {
		if !spec.CanResolve {
			continue
		}
		checkID = strings.TrimSpace(checkID)
		if checkID == "" {
			continue
		}
		suiteKey := strings.TrimSpace(spec.SuiteKey)
		current := presentByCheck[checkID]
		if current == nil {
			current = map[string]bool{} // empty set => resolve all actives for this check (within suite, if provided)
		}

		var rows *sql.Rows
		var err error
		if suiteKey != "" {
			rows, err = tx.QueryContext(ctx, `
SELECT finding_id
  FROM sf_policy_report_findings_agg
 WHERE workspace_id=$1 AND forward_network_id=$2 AND check_id=$3 AND status='ACTIVE'
   AND COALESCE(finding->>'suiteKey','') = $4
`, run.WorkspaceID, run.ForwardNetworkID, checkID, suiteKey)
		} else {
			rows, err = tx.QueryContext(ctx, `
SELECT finding_id
  FROM sf_policy_report_findings_agg
 WHERE workspace_id=$1 AND forward_network_id=$2 AND check_id=$3 AND status='ACTIVE'
`, run.WorkspaceID, run.ForwardNetworkID, checkID)
		}
		if err != nil {
			return err
		}
		var active []string
		for rows.Next() {
			var fid string
			if err := rows.Scan(&fid); err != nil {
				_ = rows.Close()
				return err
			}
			fid = strings.TrimSpace(fid)
			if fid != "" {
				active = append(active, fid)
			}
		}
		_ = rows.Close()

		for _, fid := range active {
			if current[fid] {
				continue
			}
			if suiteKey != "" {
				_, err := tx.ExecContext(ctx, `
UPDATE sf_policy_report_findings_agg
   SET status='RESOLVED',
       resolved_at=$1,
       last_run_id=$2,
       updated_at=now()
 WHERE workspace_id=$3 AND forward_network_id=$4 AND check_id=$5 AND finding_id=$6 AND status='ACTIVE'
   AND COALESCE(finding->>'suiteKey','') = $7
`, finishedAt, run.ID, run.WorkspaceID, run.ForwardNetworkID, checkID, fid, suiteKey)
				if err != nil {
					return err
				}
				continue
			}

			_, err := tx.ExecContext(ctx, `
UPDATE sf_policy_report_findings_agg
   SET status='RESOLVED',
       resolved_at=$1,
       last_run_id=$2,
       updated_at=now()
 WHERE workspace_id=$3 AND forward_network_id=$4 AND check_id=$5 AND finding_id=$6 AND status='ACTIVE'
`, finishedAt, run.ID, run.WorkspaceID, run.ForwardNetworkID, checkID, fid)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
