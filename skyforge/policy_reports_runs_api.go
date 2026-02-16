package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"github.com/google/uuid"
)

type PolicyReportListRunsRequest struct {
	ForwardNetworkID string `query:"forwardNetworkId" encore:"optional"`
	PackID           string `query:"packId" encore:"optional"`
	Status           string `query:"status" encore:"optional"`
	Limit            int    `query:"limit" encore:"optional"`
}

type PolicyReportListRunFindingsRequest struct {
	CheckID string `query:"checkId" encore:"optional"`
	Limit   int    `query:"limit" encore:"optional"`
}

type PolicyReportListFindingsRequest struct {
	ForwardNetworkID string `query:"forwardNetworkId" encore:"optional"`
	CheckID          string `query:"checkId" encore:"optional"`
	Status           string `query:"status" encore:"optional"`
	Limit            int    `query:"limit" encore:"optional"`
}

func policyReportsExecuteCheck(ctx context.Context, client *forwardClient, networkID string, snapshotID string, checkID string, params JSONMap, queryOptions JSONMap) (*PolicyReportNQEResponse, error) {
	queryText, err := policyReportsReadNQE(checkID)
	if err != nil {
		return nil, err
	}

	merged := JSONMap{}
	for k, v := range policyReportsCatalogDefaultsFor(checkID) {
		merged[k] = v
	}
	for k, v := range params {
		merged[k] = v
	}

	query := url.Values{}
	query.Set("networkId", networkID)
	if v := strings.TrimSpace(snapshotID); v != "" {
		query.Set("snapshotId", v)
	}
	payload := map[string]any{"query": queryText}
	if len(merged) > 0 {
		payload["parameters"] = merged
	}
	if queryOptions != nil {
		payload["queryOptions"] = queryOptions
	}

	resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("checkId", strings.TrimSpace(checkID)).Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	out, err := policyReportsNormalizeNQEResponseForCheck(checkID, body)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// policyReportsApplyResultLimits truncates per-check result arrays to keep stored runs bounded.
// Returns a map of checkId->canResolve, where false means results were truncated and should not
// be used to resolve missing findings in the aggregate table.
func policyReportsApplyResultLimits(order []string, results map[string]*PolicyReportNQEResponse, maxPerCheck, maxTotal int) map[string]policyReportsResolveSpec {
	canResolve := map[string]policyReportsResolveSpec{}
	if results == nil {
		return canResolve
	}
	if maxPerCheck <= 0 && maxTotal <= 0 {
		for k := range results {
			canResolve[k] = policyReportsResolveSpec{CanResolve: true}
		}
		return canResolve
	}

	remaining := maxTotal
	if remaining <= 0 {
		remaining = int(^uint(0) >> 1) // "infinite"
	}

	for _, checkID := range order {
		r := results[checkID]
		if r == nil {
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(r.Results, &arr); err != nil {
			canResolve[checkID] = policyReportsResolveSpec{CanResolve: false}
			continue
		}
		origLen := len(arr)

		limit := origLen
		if maxPerCheck > 0 && limit > maxPerCheck {
			limit = maxPerCheck
		}
		if remaining >= 0 && limit > remaining {
			limit = remaining
		}
		if limit < 0 {
			limit = 0
		}

		truncated := false
		if limit < origLen {
			arr = arr[:limit]
			truncated = true
			nb, err := json.Marshal(arr)
			if err == nil {
				r.Results = nb
			}
		}
		remaining -= limit
		if remaining < 0 {
			remaining = 0
		}
		canResolve[checkID] = policyReportsResolveSpec{CanResolve: !truncated}
	}
	return canResolve
}

// CreateUserPolicyReportRun executes a pack and persists the run + findings in the Skyforge DB.
func (s *Service) CreateUserPolicyReportRun(ctx context.Context, id string, req *PolicyReportCreateRunRequest) (*PolicyReportCreateRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	networkID := strings.TrimSpace(req.ForwardNetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("forwardNetworkId is required").Err()
	}
	packID := strings.TrimSpace(req.PackID)
	if packID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("packId is required").Err()
	}

	packs, err := loadPolicyReportPacks()
	if err != nil || packs == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("packs unavailable").Err()
	}
	var pack *PolicyReportPack
	for i := range packs.Packs {
		if strings.EqualFold(strings.TrimSpace(packs.Packs[i].ID), packID) {
			pack = &packs.Packs[i]
			break
		}
	}
	if pack == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("pack not found").Err()
	}

	startedAt := time.Now().UTC()

	fwdClient, err := s.policyReportsForwardClient(ctx, pc.context.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}

	results := map[string]*PolicyReportNQEResponse{}
	checkOrder := make([]string, 0, len(pack.Checks))
	for _, chk := range pack.Checks {
		checkID := strings.TrimSpace(chk.ID)
		if checkID == "" {
			continue
		}
		checkOrder = append(checkOrder, checkID)
		out, err := policyReportsExecuteCheck(ctx, fwdClient, networkID, strings.TrimSpace(req.SnapshotID), checkID, chk.Parameters, req.QueryOptions)
		if err != nil {
			return nil, err
		}
		results[checkID] = out
	}

	resolveChecks := policyReportsApplyResultLimits(checkOrder, results, req.MaxPerCheck, req.MaxTotal)

	// Normalize to check totals and extract stored violation findings.
	checks := make([]PolicyReportRunCheck, 0, len(checkOrder))
	var violationFindings []policyReportsViolationFinding
	for _, checkID := range checkOrder {
		r := results[checkID]
		if r == nil {
			continue
		}
		checks = append(checks, PolicyReportRunCheck{
			CheckID: checkID,
			Total:   r.Total,
		})
		vf, _ := policyReportsExtractViolationFindings(checkID, r)
		violationFindings = append(violationFindings, vf...)
	}

	finishedAt := time.Now().UTC()

	reqJSON, _ := json.Marshal(req)

	run := PolicyReportRun{
		ID:               uuid.New().String(),
		OwnerUsername:    pc.context.ID,
		ForwardNetworkID: networkID,
		SnapshotID:       strings.TrimSpace(req.SnapshotID),
		PackID:           packID,
		Title:            "",
		Status:           "SUCCEEDED",
		CreatedBy:        strings.ToLower(strings.TrimSpace(pc.claims.Username)),
		StartedAt:        startedAt,
		FinishedAt:       &finishedAt,
		Request:          reqJSON,
	}

	// Attach run ids.
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

	if err := persistPolicyReportRun(ctx, s.db, &run, checks, findings, resolveChecks); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist run").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.run.create", map[string]any{
		"id":               run.ID,
		"forwardNetworkId": run.ForwardNetworkID,
		"packId":           run.PackID,
		"status":           run.Status,
	})

	return &PolicyReportCreateRunResponse{
		Run:     run,
		Checks:  checks,
		Results: results,
	}, nil
}

// CreateUserPolicyReportCustomRun executes a list of checks and persists the run + findings.
func (s *Service) CreateUserPolicyReportCustomRun(ctx context.Context, id string, req *PolicyReportCreateCustomRunRequest) (*PolicyReportCreateCustomRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	networkID := strings.TrimSpace(req.ForwardNetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("forwardNetworkId is required").Err()
	}

	checkSpecs := req.Checks
	if len(checkSpecs) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("checks is required").Err()
	}
	seen := map[string]bool{}
	for _, spec := range checkSpecs {
		cid := strings.TrimSpace(spec.CheckID)
		if cid == "" {
			continue
		}
		if seen[cid] {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("duplicate checkId in checks").Meta("checkId", cid).Err()
		}
		seen[cid] = true
	}

	packID := strings.TrimSpace(req.PackID)
	if packID == "" {
		packID = "custom"
	}

	startedAt := time.Now().UTC()
	fwdClient, err := s.policyReportsForwardClient(ctx, pc.context.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}

	// Execute checks in request order; de-dupe ids in response map.
	results := map[string]*PolicyReportNQEResponse{}
	checkOrder := make([]string, 0, len(checkSpecs))
	for _, spec := range checkSpecs {
		checkID := strings.TrimSpace(spec.CheckID)
		if checkID == "" {
			continue
		}
		checkOrder = append(checkOrder, checkID)
		out, err := policyReportsExecuteCheck(ctx, fwdClient, networkID, strings.TrimSpace(req.SnapshotID), checkID, spec.Parameters, req.QueryOptions)
		if err != nil {
			return nil, err
		}
		results[checkID] = out
	}
	resolveChecks := policyReportsApplyResultLimits(checkOrder, results, req.MaxPerCheck, req.MaxTotal)

	checks := make([]PolicyReportRunCheck, 0, len(checkOrder))
	var violationFindings []policyReportsViolationFinding
	for _, checkID := range checkOrder {
		r := results[checkID]
		if r == nil {
			continue
		}
		checks = append(checks, PolicyReportRunCheck{CheckID: checkID, Total: r.Total})
		vf, _ := policyReportsExtractViolationFindings(checkID, r)
		violationFindings = append(violationFindings, vf...)
	}
	finishedAt := time.Now().UTC()

	reqJSON, _ := json.Marshal(req)
	run := PolicyReportRun{
		ID:               uuid.New().String(),
		OwnerUsername:    pc.context.ID,
		ForwardNetworkID: networkID,
		SnapshotID:       strings.TrimSpace(req.SnapshotID),
		PackID:           packID,
		Title:            strings.TrimSpace(req.Title),
		Status:           "SUCCEEDED",
		CreatedBy:        strings.ToLower(strings.TrimSpace(pc.claims.Username)),
		StartedAt:        startedAt,
		FinishedAt:       &finishedAt,
		Request:          reqJSON,
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

	if err := persistPolicyReportRun(ctx, s.db, &run, checks, findings, resolveChecks); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist run").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.run.create_custom", map[string]any{
		"id":               run.ID,
		"forwardNetworkId": run.ForwardNetworkID,
		"packId":           run.PackID,
		"status":           run.Status,
	})

	return &PolicyReportCreateCustomRunResponse{
		Run:     run,
		Checks:  checks,
		Results: results,
	}, nil
}

// ListUserPolicyReportRuns lists stored Policy Report runs.
func (s *Service) ListUserPolicyReportRuns(ctx context.Context, id string, req *PolicyReportListRunsRequest) (*PolicyReportListRunsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	var forwardNetworkID, packID, status string
	limit := 50
	if req != nil {
		forwardNetworkID = strings.TrimSpace(req.ForwardNetworkID)
		packID = strings.TrimSpace(req.PackID)
		status = strings.TrimSpace(req.Status)
		if req.Limit > 0 {
			limit = req.Limit
		}
	}

	runs, err := listPolicyReportRuns(ctx, s.db, pc.context.ID, forwardNetworkID, packID, status, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListRunsResponse{Runs: []PolicyReportRun{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list runs").Err()
	}
	return &PolicyReportListRunsResponse{Runs: runs}, nil
}

// GetUserPolicyReportRun returns a stored run and its per-check totals.
func (s *Service) GetUserPolicyReportRun(ctx context.Context, id string, runId string) (*PolicyReportGetRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	run, checks, err := getPolicyReportRun(ctx, s.db, pc.context.ID, runId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("run not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load run").Err()
	}
	return &PolicyReportGetRunResponse{Run: *run, Checks: checks}, nil
}

// ListUserPolicyReportRunFindings lists stored violation findings for a run.
func (s *Service) ListUserPolicyReportRunFindings(ctx context.Context, id string, runId string, req *PolicyReportListRunFindingsRequest) (*PolicyReportListRunFindingsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	checkID := ""
	limit := 500
	if req != nil {
		checkID = strings.TrimSpace(req.CheckID)
		if req.Limit > 0 {
			limit = req.Limit
		}
	}

	findings, err := listPolicyReportRunFindings(ctx, s.db, pc.context.ID, runId, checkID, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListRunFindingsResponse{Findings: []PolicyReportRunFinding{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list run findings").Err()
	}
	return &PolicyReportListRunFindingsResponse{Findings: findings}, nil
}

// ListUserPolicyReportFindings lists aggregated findings across stored runs.
func (s *Service) ListUserPolicyReportFindings(ctx context.Context, id string, req *PolicyReportListFindingsRequest) (*PolicyReportListFindingsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	forwardNetworkID := ""
	checkID := ""
	status := ""
	limit := 500
	if req != nil {
		forwardNetworkID = strings.TrimSpace(req.ForwardNetworkID)
		checkID = strings.TrimSpace(req.CheckID)
		status = strings.TrimSpace(req.Status)
		if req.Limit > 0 {
			limit = req.Limit
		}
	}

	findings, err := listPolicyReportFindingsAgg(ctx, s.db, pc.context.ID, forwardNetworkID, checkID, status, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListFindingsResponse{Findings: []PolicyReportFindingAgg{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list findings").Err()
	}
	return &PolicyReportListFindingsResponse{Findings: findings}, nil
}
