package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"encore.dev/beta/errs"
)

func (s *Service) policyReportsForwardClient(ctx context.Context, workspaceID, username, forwardNetworkID string) (*forwardClient, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)

	// Preferred: per-user per-network credentials (Policy Reports specific).
	if strings.TrimSpace(username) != "" && strings.TrimSpace(forwardNetworkID) != "" {
		if pr, err := getPolicyReportForwardCreds(ctx, s.db, box, workspaceID, username, forwardNetworkID); err == nil && pr != nil {
			return newForwardClient(forwardCredentials{
				BaseURL:       pr.BaseURL,
				SkipTLSVerify: pr.SkipTLSVerify,
				Username:      pr.Username,
				Password:      pr.Password,
			})
		}
	}

	// Fallback: legacy per-user Forward credentials.
	if strings.TrimSpace(username) != "" {
		// Prefer the user's default collector config if present; otherwise fall back to legacy per-user credentials.
		if cfg, err := s.forwardConfigForUser(ctx, strings.ToLower(strings.TrimSpace(username))); err == nil && cfg != nil {
			return newForwardClient(forwardCredentials{
				BaseURL:       cfg.BaseURL,
				SkipTLSVerify: cfg.SkipTLSVerify,
				Username:      cfg.Username,
				Password:      cfg.Password,
			})
		}
	}

	// Final fallback: workspace-level Forward credentials.
	rec, err := getWorkspaceForwardCredentials(ctx, s.db, box, workspaceID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
	}
	if rec == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user/network or workspace").Err()
	}
	client, err := newForwardClient(*rec)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return client, nil
}

type PolicyReportChecksResponse struct {
	Catalog *PolicyReportCatalog       `json:"catalog,omitempty"`
	Checks  []PolicyReportCatalogCheck `json:"checks"`
	Files   []string                   `json:"files"`
}

type PolicyReportCheckResponse struct {
	Check   *PolicyReportCatalogCheck `json:"check,omitempty"`
	Content string                    `json:"content"`
}

// GetWorkspacePolicyReportCatalog returns the embedded Policy Reports check catalog.
//
//encore:api auth method=GET path=/api/workspaces/:id/policy-reports/catalog
func (s *Service) GetWorkspacePolicyReportCatalog(ctx context.Context, id string) (*PolicyReportCatalog, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	cat, err := loadPolicyReportCatalog()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load catalog").Err()
	}
	return cat, nil
}

// GetWorkspacePolicyReportPacks returns the embedded Policy Reports packs definition.
//
//encore:api auth method=GET path=/api/workspaces/:id/policy-reports/packs
func (s *Service) GetWorkspacePolicyReportPacks(ctx context.Context, id string) (*PolicyReportPacks, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	packs, err := loadPolicyReportPacks()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load packs").Err()
	}
	return packs, nil
}

// GetWorkspacePolicyReportChecks lists known checks (catalog + embedded .nqe files).
//
//encore:api auth method=GET path=/api/workspaces/:id/policy-reports/checks
func (s *Service) GetWorkspacePolicyReportChecks(ctx context.Context, id string) (*PolicyReportChecksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	files, err := policyReportsListNQEFiles()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list checks").Err()
	}

	cat, _ := loadPolicyReportCatalog()
	checks := []PolicyReportCatalogCheck{}
	if cat != nil {
		exists := map[string]bool{}
		for _, f := range files {
			exists[f] = true
		}
		for _, c := range cat.Checks {
			if exists[strings.TrimSpace(c.ID)] {
				checks = append(checks, c)
			}
		}
	} else {
		for _, f := range files {
			checks = append(checks, PolicyReportCatalogCheck{ID: f})
		}
	}

	sort.Slice(checks, func(i, j int) bool {
		return strings.ToLower(checks[i].ID) < strings.ToLower(checks[j].ID)
	})

	return &PolicyReportChecksResponse{
		Catalog: cat,
		Checks:  checks,
		Files:   files,
	}, nil
}

// GetWorkspacePolicyReportCheck returns the .nqe file content for a given check.
//
//encore:api auth method=GET path=/api/workspaces/:id/policy-reports/checks/:checkId
func (s *Service) GetWorkspacePolicyReportCheck(ctx context.Context, id string, checkId string) (*PolicyReportCheckResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	content, err := policyReportsReadNQE(checkId)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("check not found").Err()
	}

	var check *PolicyReportCatalogCheck
	if cat, err := loadPolicyReportCatalog(); err == nil && cat != nil {
		idNorm := strings.TrimSpace(checkId)
		if !strings.HasSuffix(strings.ToLower(idNorm), ".nqe") {
			idNorm += ".nqe"
		}
		for i := range cat.Checks {
			if strings.TrimSpace(cat.Checks[i].ID) == idNorm {
				check = &cat.Checks[i]
				break
			}
		}
	}

	return &PolicyReportCheckResponse{
		Check:   check,
		Content: content,
	}, nil
}

// GetWorkspacePolicyReportSnapshots lists snapshots for a Forward network.
//
//encore:api auth method=GET path=/api/workspaces/:id/policy-reports/snapshots
func (s *Service) GetWorkspacePolicyReportSnapshots(ctx context.Context, id string, req *PolicyReportSnapshotsRequest) (*PolicyReportSnapshotsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.NetworkID) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("networkId is required").Err()
	}
	maxResults := req.MaxResults
	if maxResults <= 0 || maxResults > 500 {
		maxResults = 50
	}

	client, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, strings.TrimSpace(req.NetworkID))
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("maxResults", fmt.Sprintf("%d", maxResults))
	rawPath := "/api/networks/" + url.PathEscape(strings.TrimSpace(req.NetworkID)) + "/snapshots"
	resp, body, err := client.doJSON(ctx, http.MethodGet, rawPath, query, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward snapshots failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return &PolicyReportSnapshotsResponse{Body: body}, nil
}

// RunWorkspacePolicyReportNQE executes an NQE query and returns a normalized response.
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/nqe
func (s *Service) RunWorkspacePolicyReportNQE(ctx context.Context, id string, req *PolicyReportNQERequest) (*PolicyReportNQEResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	networkID := strings.TrimSpace(req.NetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("networkId is required").Err()
	}
	queryText := strings.TrimSpace(req.Query)
	if queryText == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("query is required").Err()
	}

	client, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("networkId", networkID)
	if v := strings.TrimSpace(req.SnapshotID); v != "" {
		query.Set("snapshotId", v)
	}
	payload := map[string]any{"query": queryText}
	if req.Parameters != nil {
		payload["parameters"] = req.Parameters
	}
	if req.QueryOptions != nil {
		payload["queryOptions"] = req.QueryOptions
	}

	resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	out, err := policyReportsNormalizeNQEResponse(body)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Err()
	}
	return out, nil
}

// RunWorkspacePolicyReportCheck executes an embedded check (.nqe) and returns a normalized response.
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/checks/run
func (s *Service) RunWorkspacePolicyReportCheck(ctx context.Context, id string, req *PolicyReportRunCheckRequest) (*PolicyReportNQEResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	networkID := strings.TrimSpace(req.NetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("networkId is required").Err()
	}
	checkID := strings.TrimSpace(req.CheckID)
	if checkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("checkId is required").Err()
	}
	queryText, err := policyReportsReadNQE(checkID)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("check not found").Err()
	}

	// Merge catalog defaults (if any) under request parameters.
	params := JSONMap{}
	for k, v := range policyReportsCatalogDefaultsFor(checkID) {
		params[k] = v
	}
	for k, v := range req.Parameters {
		params[k] = v
	}

	client, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("networkId", networkID)
	if v := strings.TrimSpace(req.SnapshotID); v != "" {
		query.Set("snapshotId", v)
	}
	payload := map[string]any{"query": queryText}
	if len(params) > 0 {
		payload["parameters"] = params
	}
	if req.QueryOptions != nil {
		payload["queryOptions"] = req.QueryOptions
	}

	resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	out, err := policyReportsNormalizeNQEResponseForCheck(checkID, body)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Err()
	}
	return out, nil
}

// RunWorkspacePolicyReportPack executes all checks in a pack (serially) and returns per-check results.
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/packs/run
func (s *Service) RunWorkspacePolicyReportPack(ctx context.Context, id string, req *PolicyReportRunPackRequest) (*PolicyReportRunPackResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	networkID := strings.TrimSpace(req.NetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("networkId is required").Err()
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

	// Reuse one Forward client for the whole pack.
	fwdClient, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}

	results := map[string]*PolicyReportNQEResponse{}
	for _, chk := range pack.Checks {
		checkID := strings.TrimSpace(chk.ID)
		if checkID == "" {
			continue
		}
		queryText, err := policyReportsReadNQE(checkID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("pack check missing").Meta("checkId", checkID).Err()
		}

		params := JSONMap{}
		for k, v := range policyReportsCatalogDefaultsFor(checkID) {
			params[k] = v
		}
		for k, v := range chk.Parameters {
			params[k] = v
		}

		query := url.Values{}
		query.Set("networkId", networkID)
		if v := strings.TrimSpace(req.SnapshotID); v != "" {
			query.Set("snapshotId", v)
		}
		payload := map[string]any{"query": queryText}
		if len(params) > 0 {
			payload["parameters"] = params
		}
		if req.QueryOptions != nil {
			payload["queryOptions"] = req.QueryOptions
		}

		resp, body, err := fwdClient.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Meta("checkId", checkID).Err()
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("checkId", checkID).Meta("upstream", strings.TrimSpace(string(body))).Err()
		}
		out, err := policyReportsNormalizeNQEResponseForCheck(checkID, body)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Meta("checkId", checkID).Err()
		}
		results[checkID] = out
	}

	return &PolicyReportRunPackResponse{
		PackID:     packID,
		NetworkID:  networkID,
		SnapshotID: strings.TrimSpace(req.SnapshotID),
		Results:    results,
	}, nil
}

// RunWorkspacePolicyReportPackDelta runs a pack on two snapshots and returns a per-check delta summary.
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/packs/delta
func (s *Service) RunWorkspacePolicyReportPackDelta(ctx context.Context, id string, req *PolicyReportPackDeltaRequest) (*PolicyReportPackDeltaResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	networkID := strings.TrimSpace(req.NetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("networkId is required").Err()
	}
	packID := strings.TrimSpace(req.PackID)
	if packID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("packId is required").Err()
	}
	baseSnap := strings.TrimSpace(req.BaselineSnapshotID)
	compSnap := strings.TrimSpace(req.CompareSnapshotID)
	if baseSnap == "" || compSnap == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("baselineSnapshotId and compareSnapshotId are required").Err()
	}

	maxSamples := req.MaxSamplesPerBucket
	if maxSamples <= 0 || maxSamples > 100 {
		maxSamples = 20
	}

	// Run the pack twice.
	baseResp, err := s.RunWorkspacePolicyReportPack(ctx, id, &PolicyReportRunPackRequest{
		NetworkID:    networkID,
		SnapshotID:   baseSnap,
		PackID:       packID,
		QueryOptions: req.QueryOptions,
	})
	if err != nil {
		return nil, err
	}
	compResp, err := s.RunWorkspacePolicyReportPack(ctx, id, &PolicyReportRunPackRequest{
		NetworkID:    networkID,
		SnapshotID:   compSnap,
		PackID:       packID,
		QueryOptions: req.QueryOptions,
	})
	if err != nil {
		return nil, err
	}

	_ = pc

	checkIDs := map[string]bool{}
	for k := range baseResp.Results {
		checkIDs[k] = true
	}
	for k := range compResp.Results {
		checkIDs[k] = true
	}
	ids := make([]string, 0, len(checkIDs))
	for k := range checkIDs {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	deltas := make([]PolicyReportPackDeltaCheck, 0, len(ids))
	for _, chk := range ids {
		base := baseResp.Results[chk]
		comp := compResp.Results[chk]

		baseItems := []json.RawMessage{}
		compItems := []json.RawMessage{}
		if base != nil && len(base.Results) > 0 {
			_ = json.Unmarshal(base.Results, &baseItems)
		}
		if comp != nil && len(comp.Results) > 0 {
			_ = json.Unmarshal(comp.Results, &compItems)
		}

		baseSet := map[string]json.RawMessage{}
		compSet := map[string]json.RawMessage{}
		for _, raw := range baseItems {
			id := policyReportsExtractFindingID(raw)
			if id == "" {
				id = policyReportsComputeFindingID(chk, raw)
			}
			baseSet[id] = raw
		}
		for _, raw := range compItems {
			id := policyReportsExtractFindingID(raw)
			if id == "" {
				id = policyReportsComputeFindingID(chk, raw)
			}
			compSet[id] = raw
		}

		newSamples := make([]json.RawMessage, 0, maxSamples)
		oldSamples := make([]json.RawMessage, 0, maxSamples)
		type changedSample struct {
			FindingID string          `json:"findingId"`
			Baseline  json.RawMessage `json:"baseline"`
			Compare   json.RawMessage `json:"compare"`
		}
		changedSamples := make([]changedSample, 0, maxSamples)
		newCount := 0
		resolvedCount := 0
		changedCount := 0

		for id, v := range compSet {
			if _, ok := baseSet[id]; ok {
				continue
			}
			newCount++
			if len(newSamples) < maxSamples {
				newSamples = append(newSamples, v)
			}
		}
		for id, v := range baseSet {
			if _, ok := compSet[id]; ok {
				continue
			}
			resolvedCount++
			if len(oldSamples) < maxSamples {
				oldSamples = append(oldSamples, v)
			}
		}

		ignore := map[string]bool{"findingId": true}
		for id, baseRaw := range baseSet {
			compRaw, ok := compSet[id]
			if !ok {
				continue
			}
			baseHash := policyReportsCanonicalJSONHash(baseRaw, ignore)
			compHash := policyReportsCanonicalJSONHash(compRaw, ignore)
			if baseHash == compHash {
				continue
			}
			changedCount++
			if len(changedSamples) < maxSamples {
				changedSamples = append(changedSamples, changedSample{
					FindingID: id,
					Baseline:  baseRaw,
					Compare:   compRaw,
				})
			}
		}

		newJSON, _ := json.Marshal(newSamples)
		oldJSON, _ := json.Marshal(oldSamples)
		changedJSON, _ := json.Marshal(changedSamples)
		baselineTotal := 0
		compareTotal := 0
		if base != nil {
			baselineTotal = base.Total
		}
		if comp != nil {
			compareTotal = comp.Total
		}

		deltas = append(deltas, PolicyReportPackDeltaCheck{
			CheckID:        chk,
			BaselineTotal:  baselineTotal,
			CompareTotal:   compareTotal,
			NewCount:       newCount,
			ResolvedCount:  resolvedCount,
			ChangedCount:   changedCount,
			NewSamples:     newJSON,
			OldSamples:     oldJSON,
			ChangedSamples: changedJSON,
		})
	}

	return &PolicyReportPackDeltaResponse{
		PackID:             packID,
		NetworkID:          networkID,
		BaselineSnapshotID: baseSnap,
		CompareSnapshotID:  compSnap,
		Checks:             deltas,
	}, nil
}
