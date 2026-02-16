package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/skyforgeconfig"
	"encore.dev/cron"
	"encore.dev/rlog"

	"github.com/google/uuid"
)

// Cron job: run due Policy Reports presets.
//
//encore:api private method=POST path=/internal/cron/policy-reports/presets
func CronRunPolicyReportPresets(ctx context.Context) error {
	db, err := openSkyforgeDB(ctx)
	if err != nil || db == nil {
		return err
	}
	ctxReq, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	cfg := skyforgeconfig.LoadConfig(skyforgeEncoreCfg, getSecrets())
	sessionSecret := cfg.SessionSecret
	if strings.TrimSpace(sessionSecret) == "" {
		return fmt.Errorf("session secret unavailable")
	}

	rows, err := db.QueryContext(ctxReq, `
SELECT id::text, owner_username, forward_network_id, kind, pack_id, COALESCE(title_template,''), snapshot_id,
       checks, query_options, max_per_check, max_total, interval_minutes, owner_username
  FROM sf_policy_report_presets
 WHERE enabled=true
   AND next_run_at IS NOT NULL
   AND next_run_at <= now()
 ORDER BY next_run_at ASC
 LIMIT 20`)
	if err != nil {
		if isMissingDBRelation(err) {
			return nil
		}
		return err
	}
	defer rows.Close()

	type duePreset struct {
		id               string
		ownerID          string
		forwardNetworkID string
		kind             string
		packID           string
		titleTemplate    string
		snapshotID       string
		checksJSON       []byte
		queryOptionsJSON []byte
		maxPerCheck      int
		maxTotal         int
		intervalMinutes  int
		ownerUsername    string
	}

	var due []duePreset
	for rows.Next() {
		var p duePreset
		if err := rows.Scan(&p.id, &p.ownerID, &p.forwardNetworkID, &p.kind, &p.packID, &p.titleTemplate, &p.snapshotID,
			&p.checksJSON, &p.queryOptionsJSON, &p.maxPerCheck, &p.maxTotal, &p.intervalMinutes, &p.ownerUsername); err != nil {
			continue
		}
		p.id = strings.TrimSpace(p.id)
		p.ownerID = strings.TrimSpace(p.ownerID)
		p.forwardNetworkID = strings.TrimSpace(p.forwardNetworkID)
		p.kind = strings.ToUpper(strings.TrimSpace(p.kind))
		p.packID = strings.TrimSpace(p.packID)
		p.titleTemplate = strings.TrimSpace(p.titleTemplate)
		p.snapshotID = strings.TrimSpace(p.snapshotID)
		p.ownerUsername = strings.ToLower(strings.TrimSpace(p.ownerUsername))
		if p.id == "" || p.ownerID == "" || p.forwardNetworkID == "" || p.ownerUsername == "" {
			continue
		}
		due = append(due, p)
	}

	ran := 0
	for _, p := range due {
		if err := runPolicyReportPresetInternal(ctxReq, db, sessionSecret, p); err != nil {
			rlog.Error("policy reports preset run failed", "preset_id", p.id, "err", err)
		} else {
			ran++
		}
	}
	if ran > 0 {
		rlog.Info("policy reports presets executed", "count", ran)
	}
	return nil
}

var (
	_ = cron.NewJob("skyforge-policy-reports-presets", cron.JobConfig{
		Title:    "Run Policy Reports presets",
		Endpoint: CronRunPolicyReportPresets,
		Every:    1 * cron.Minute,
	})
)

func renderPresetTitle(template string, forwardNetworkID, packID string, startedAt time.Time) string {
	t := strings.TrimSpace(template)
	if t == "" {
		if packID != "" {
			return packID
		}
		return "policy-report"
	}
	// Extremely small templating surface to avoid pulling in deps.
	out := t
	out = strings.ReplaceAll(out, "{forwardNetworkId}", forwardNetworkID)
	out = strings.ReplaceAll(out, "{packId}", packID)
	out = strings.ReplaceAll(out, "{date}", startedAt.UTC().Format("2006-01-02"))
	out = strings.ReplaceAll(out, "{timestamp}", startedAt.UTC().Format(time.RFC3339))
	return out
}

func runPolicyReportPresetInternal(ctx context.Context, db *sql.DB, sessionSecret string, p struct {
	id               string
	ownerID          string
	forwardNetworkID string
	kind             string
	packID           string
	titleTemplate    string
	snapshotID       string
	checksJSON       []byte
	queryOptionsJSON []byte
	maxPerCheck      int
	maxTotal         int
	intervalMinutes  int
	ownerUsername    string
}) error {
	startedAt := time.Now().UTC()

	client, err := policyReportsForwardClientFor(ctx, db, sessionSecret, p.ownerID, p.ownerUsername, p.forwardNetworkID)
	if err != nil {
		_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, err.Error())
		return err
	}

	var queryOptions JSONMap
	_ = json.Unmarshal(p.queryOptionsJSON, &queryOptions)

	// PATHS presets are not NQE-backed; they run the Paths Assurance suite and persist results as a run.
	if p.kind == "PATHS" {
		var specs []PolicyReportPresetCheckSpec
		_ = json.Unmarshal(p.checksJSON, &specs)
		if len(specs) == 0 {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, "preset checks empty")
			return fmt.Errorf("preset checks empty")
		}

		var spec *PolicyReportPresetCheckSpec
		for i := range specs {
			if strings.EqualFold(strings.TrimSpace(specs[i].CheckID), "paths-enforcement-bypass") {
				spec = &specs[i]
				break
			}
		}
		if spec == nil {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, "missing paths-enforcement-bypass check")
			return fmt.Errorf("missing paths-enforcement-bypass check")
		}

		var storeReq PolicyReportPathsEnforcementBypassStoreRequest
		if b, _ := json.Marshal(spec.Parameters); len(b) > 0 && string(b) != "null" {
			_ = json.Unmarshal(b, &storeReq)
		}
		storeReq.ForwardNetworkID = p.forwardNetworkID
		storeReq.SnapshotID = p.snapshotID
		storeReq.Title = renderPresetTitle(p.titleTemplate, p.forwardNetworkID, "paths-assurance", startedAt)

		// Convert store request shape into the live evaluator input (title is ignored).
		var live PolicyReportPathsEnforcementBypassRequest
		if b, _ := json.Marshal(storeReq); len(b) > 0 {
			_ = json.Unmarshal(b, &live)
		}
		live.ForwardNetworkID = storeReq.ForwardNetworkID
		live.SnapshotID = storeReq.SnapshotID

		out, checkID, err := policyReportsPathsEnforcementBypassEvalWithClient(ctx, client, &live)
		if err != nil {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, err.Error())
			return err
		}
		if strings.TrimSpace(checkID) == "" {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, "failed to compute suite check id")
			return fmt.Errorf("failed to compute suite check id")
		}

		finishedAt := time.Now().UTC()
		runID := uuid.New().String()

		reqAny := map[string]any{
			"presetId":         p.id,
			"presetKind":       p.kind,
			"snapshotId":       p.snapshotID,
			"cron":             true,
			"ownerUsername":    p.ownerUsername,
			"forwardNetworkId": p.forwardNetworkID,
			"paths":            storeReq,
		}
		reqJSON, _ := json.Marshal(reqAny)

		run := PolicyReportRun{
			ID:               runID,
			OwnerUsername:    p.ownerID,
			ForwardNetworkID: p.forwardNetworkID,
			SnapshotID:       strings.TrimSpace(p.snapshotID),
			PackID:           "paths-assurance",
			Title:            strings.TrimSpace(storeReq.Title),
			Status:           "SUCCEEDED",
			CreatedBy:        p.ownerUsername,
			StartedAt:        startedAt,
			FinishedAt:       &finishedAt,
			Request:          reqJSON,
		}

		checks := []PolicyReportRunCheck{{
			RunID:   run.ID,
			CheckID: checkID,
			Total:   0,
		}}
		if out != nil {
			checks[0].Total = out.Total
		}

		vf, _ := policyReportsExtractViolationFindings(checkID, out)
		findings := make([]PolicyReportRunFinding, 0, len(vf))
		for _, f := range vf {
			findings = append(findings, PolicyReportRunFinding{
				RunID:     run.ID,
				CheckID:   f.CheckID,
				FindingID: f.FindingID,
				RiskScore: f.RiskScore,
				AssetKey:  f.AssetKey,
				Finding:   f.Finding,
			})
		}

		kept := make([]PolicyReportPathQuery, 0, len(live.Queries))
		for _, q := range live.Queries {
			if strings.TrimSpace(q.DstIP) == "" {
				continue
			}
			kept = append(kept, q)
		}
		suiteKey := suiteKeyForPathsAssurance(&live, kept)
		suiteKey12 := suiteKey
		if len(suiteKey12) > 12 {
			suiteKey12 = suiteKey12[:12]
		}
		resolveChecks := map[string]policyReportsResolveSpec{
			checkID: {CanResolve: true, SuiteKey: suiteKey12},
		}
		if err := persistPolicyReportRun(ctx, db, &run, checks, findings, resolveChecks); err != nil {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", finishedAt, p.intervalMinutes, err.Error())
			return err
		}

		_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, run.ID, finishedAt, p.intervalMinutes, "")
		return nil
	}

	results := map[string]*PolicyReportNQEResponse{}
	checkOrder := []string{}
	if p.kind == "PACK" {
		packs, err := loadPolicyReportPacks()
		if err != nil || packs == nil {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, "packs unavailable")
			return fmt.Errorf("packs unavailable")
		}
		var pack *PolicyReportPack
		for i := range packs.Packs {
			if strings.EqualFold(strings.TrimSpace(packs.Packs[i].ID), strings.TrimSpace(p.packID)) {
				pack = &packs.Packs[i]
				break
			}
		}
		if pack == nil {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, "pack not found")
			return fmt.Errorf("pack not found: %s", p.packID)
		}
		for _, chk := range pack.Checks {
			cid := strings.TrimSpace(chk.ID)
			if cid == "" {
				continue
			}
			checkOrder = append(checkOrder, cid)
			out, err := policyReportsExecuteCheck(ctx, client, p.forwardNetworkID, p.snapshotID, cid, chk.Parameters, queryOptions)
			if err != nil {
				_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, err.Error())
				return err
			}
			results[cid] = out
		}
	} else {
		var specs []PolicyReportPresetCheckSpec
		_ = json.Unmarshal(p.checksJSON, &specs)
		if len(specs) == 0 {
			_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, "preset checks empty")
			return fmt.Errorf("preset checks empty")
		}
		seen := map[string]bool{}
		for _, spec := range specs {
			cid := strings.TrimSpace(spec.CheckID)
			if cid == "" {
				continue
			}
			if seen[cid] {
				continue
			}
			seen[cid] = true
			checkOrder = append(checkOrder, cid)
			out, err := policyReportsExecuteCheck(ctx, client, p.forwardNetworkID, p.snapshotID, cid, spec.Parameters, queryOptions)
			if err != nil {
				_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", startedAt, p.intervalMinutes, err.Error())
				return err
			}
			results[cid] = out
		}
	}

	resolveChecks := policyReportsApplyResultLimits(checkOrder, results, p.maxPerCheck, p.maxTotal)

	// Convert to stored checks+findings.
	checks := make([]PolicyReportRunCheck, 0, len(checkOrder))
	var violationFindings []policyReportsViolationFinding
	for _, cid := range checkOrder {
		r := results[cid]
		if r == nil {
			continue
		}
		checks = append(checks, PolicyReportRunCheck{CheckID: cid, Total: r.Total})
		vf, _ := policyReportsExtractViolationFindings(cid, r)
		violationFindings = append(violationFindings, vf...)
	}

	finishedAt := time.Now().UTC()
	runID := uuid.New().String()

	// Store "request" as a small blob for traceability.
	reqAny := map[string]any{
		"presetId":         p.id,
		"presetKind":       p.kind,
		"packId":           p.packID,
		"snapshotId":       p.snapshotID,
		"queryOptions":     queryOptions,
		"maxPerCheck":      p.maxPerCheck,
		"maxTotal":         p.maxTotal,
		"cron":             true,
		"ownerUsername":    p.ownerUsername,
		"forwardNetworkId": p.forwardNetworkID,
	}
	reqJSON, _ := json.Marshal(reqAny)

	run := PolicyReportRun{
		ID:               runID,
		OwnerUsername:    p.ownerID,
		ForwardNetworkID: p.forwardNetworkID,
		SnapshotID:       strings.TrimSpace(p.snapshotID),
		PackID: func() string {
			if strings.TrimSpace(p.packID) != "" {
				return strings.TrimSpace(p.packID)
			}
			if p.kind == "CUSTOM" {
				return "custom"
			}
			return "pack"
		}(),
		Title:      renderPresetTitle(p.titleTemplate, p.forwardNetworkID, p.packID, startedAt),
		Status:     "SUCCEEDED",
		CreatedBy:  p.ownerUsername,
		StartedAt:  startedAt,
		FinishedAt: &finishedAt,
		Request:    reqJSON,
	}

	for i := range checks {
		checks[i].RunID = run.ID
	}
	findings := make([]PolicyReportRunFinding, 0, len(violationFindings))
	for _, f := range violationFindings {
		findings = append(findings, PolicyReportRunFinding{
			RunID:     run.ID,
			CheckID:   f.CheckID,
			FindingID: f.FindingID,
			RiskScore: f.RiskScore,
			AssetKey:  f.AssetKey,
			Finding:   f.Finding,
		})
	}

	if err := persistPolicyReportRun(ctx, db, &run, checks, findings, resolveChecks); err != nil {
		_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, "", finishedAt, p.intervalMinutes, err.Error())
		return err
	}

	// Update preset run pointers and schedule next run.
	_ = bumpPresetSchedule(ctx, db, p.ownerID, p.id, run.ID, finishedAt, p.intervalMinutes, "")
	return nil
}

func bumpPresetSchedule(ctx context.Context, db *sql.DB, ownerID, presetID, runID string, finishedAt time.Time, intervalMinutes int, lastErr string) error {
	if db == nil {
		return nil
	}
	ownerID = strings.TrimSpace(ownerID)
	presetID = strings.TrimSpace(presetID)
	if ownerID == "" || presetID == "" {
		return nil
	}
	intervalMinutes = normalizeIntervalMinutes(intervalMinutes)
	next := finishedAt.Add(time.Duration(intervalMinutes) * time.Minute)

	// Write schedule update (best-effort; don't fail cron for this).
	_, _ = db.ExecContext(ctx, `
UPDATE sf_policy_report_presets
   SET last_run_id=NULLIF($1,'')::uuid,
       last_run_at=$2,
       last_error=NULLIF($3,''),
       next_run_at=$4,
       updated_at=now()
 WHERE owner_username=$5 AND id=$6
`, strings.TrimSpace(runID), finishedAt, strings.TrimSpace(lastErr), next, ownerID, presetID)
	return nil
}
