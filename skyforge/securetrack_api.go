package skyforge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"encore.dev/beta/errs"
)

type SecureTrackChecksResponse struct {
	Catalog *SecureTrackCatalog       `json:"catalog,omitempty"`
	Checks  []SecureTrackCatalogCheck `json:"checks"`
	Files   []string                  `json:"files"`
}

type SecureTrackCheckResponse struct {
	Check   *SecureTrackCatalogCheck `json:"check,omitempty"`
	Content string                   `json:"content"`
}

func (s *Service) secureTrackForwardClient(ctx context.Context, userScopeID string) (*forwardClient, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	rec, err := getUserScopeForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), userScopeID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
	}
	if rec == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user scope").Err()
	}
	client, err := newForwardClient(*rec)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return client, nil
}

// GetUserScopeSecureTrackCatalog returns the embedded SecureTrack check catalog.
//
//encore:api auth method=GET path=/api/users/:id/securetrack/catalog
func (s *Service) GetUserScopeSecureTrackCatalog(ctx context.Context, id string) (*SecureTrackCatalog, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	cat, err := loadSecureTrackCatalog()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load catalog").Err()
	}
	return cat, nil
}

// GetUserScopeSecureTrackPacks returns the embedded SecureTrack packs definition.
//
//encore:api auth method=GET path=/api/users/:id/securetrack/packs
func (s *Service) GetUserScopeSecureTrackPacks(ctx context.Context, id string) (*SecureTrackPacks, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	packs, err := loadSecureTrackPacks()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load packs").Err()
	}
	return packs, nil
}

// GetUserScopeSecureTrackChecks lists known checks (catalog + embedded .nqe files).
//
//encore:api auth method=GET path=/api/users/:id/securetrack/checks
func (s *Service) GetUserScopeSecureTrackChecks(ctx context.Context, id string) (*SecureTrackChecksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	files, err := secureTrackListNQEFiles()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list checks").Err()
	}

	cat, _ := loadSecureTrackCatalog()
	checks := []SecureTrackCatalogCheck{}
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
			checks = append(checks, SecureTrackCatalogCheck{ID: f})
		}
	}

	sort.Slice(checks, func(i, j int) bool {
		return strings.ToLower(checks[i].ID) < strings.ToLower(checks[j].ID)
	})

	return &SecureTrackChecksResponse{
		Catalog: cat,
		Checks:  checks,
		Files:   files,
	}, nil
}

// GetUserScopeSecureTrackCheck returns the .nqe file content for a given check.
//
//encore:api auth method=GET path=/api/users/:id/securetrack/checks/:checkId
func (s *Service) GetUserScopeSecureTrackCheck(ctx context.Context, id string, checkId string) (*SecureTrackCheckResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	_ = pc

	content, err := secureTrackReadNQE(checkId)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("check not found").Err()
	}

	var check *SecureTrackCatalogCheck
	if cat, err := loadSecureTrackCatalog(); err == nil && cat != nil {
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

	return &SecureTrackCheckResponse{
		Check:   check,
		Content: content,
	}, nil
}

// GetUserScopeSecureTrackSnapshots lists snapshots for a Forward network.
//
//encore:api auth method=GET path=/api/users/:id/securetrack/snapshots
func (s *Service) GetUserScopeSecureTrackSnapshots(ctx context.Context, id string, req *SecureTrackSnapshotsRequest) (*SecureTrackSnapshotsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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

	client, err := s.secureTrackForwardClient(ctx, pc.userScope.ID)
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
	return &SecureTrackSnapshotsResponse{Body: body}, nil
}

// RunUserScopeSecureTrackNQE executes an NQE query and returns a normalized response.
//
//encore:api auth method=POST path=/api/users/:id/securetrack/nqe
func (s *Service) RunUserScopeSecureTrackNQE(ctx context.Context, id string, req *SecureTrackNQERequest) (*SecureTrackNQEResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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

	client, err := s.secureTrackForwardClient(ctx, pc.userScope.ID)
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
	out, err := secureTrackNormalizeNQEResponse(body)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Err()
	}
	return out, nil
}

// RunUserScopeSecureTrackCheck executes an embedded check (.nqe) and returns a normalized response.
//
//encore:api auth method=POST path=/api/users/:id/securetrack/checks/run
func (s *Service) RunUserScopeSecureTrackCheck(ctx context.Context, id string, req *SecureTrackRunCheckRequest) (*SecureTrackNQEResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	queryText, err := secureTrackReadNQE(checkID)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("check not found").Err()
	}

	// Merge catalog defaults (if any) under request parameters.
	params := JSONMap{}
	for k, v := range secureTrackCatalogDefaultsFor(checkID) {
		params[k] = v
	}
	for k, v := range req.Parameters {
		params[k] = v
	}

	client, err := s.secureTrackForwardClient(ctx, pc.userScope.ID)
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
	out, err := secureTrackNormalizeNQEResponse(body)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Err()
	}
	return out, nil
}

// RunUserScopeSecureTrackPack executes all checks in a pack (serially) and returns per-check results.
//
//encore:api auth method=POST path=/api/users/:id/securetrack/packs/run
func (s *Service) RunUserScopeSecureTrackPack(ctx context.Context, id string, req *SecureTrackRunPackRequest) (*SecureTrackRunPackResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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

	packs, err := loadSecureTrackPacks()
	if err != nil || packs == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("packs unavailable").Err()
	}

	var pack *SecureTrackPack
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
	fwdClient, err := s.secureTrackForwardClient(ctx, pc.userScope.ID)
	if err != nil {
		return nil, err
	}

	results := map[string]*SecureTrackNQEResponse{}
	for _, chk := range pack.Checks {
		checkID := strings.TrimSpace(chk.ID)
		if checkID == "" {
			continue
		}
		queryText, err := secureTrackReadNQE(checkID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("pack check missing").Meta("checkId", checkID).Err()
		}

		params := JSONMap{}
		for k, v := range secureTrackCatalogDefaultsFor(checkID) {
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

		resp, body, err := fwdClient.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Meta("checkId", checkID).Err()
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("checkId", checkID).Meta("upstream", strings.TrimSpace(string(body))).Err()
		}
		out, err := secureTrackNormalizeNQEResponse(body)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Meta("checkId", checkID).Err()
		}
		results[checkID] = out
	}

	return &SecureTrackRunPackResponse{
		PackID:     packID,
		NetworkID:  networkID,
		SnapshotID: strings.TrimSpace(req.SnapshotID),
		Results:    results,
	}, nil
}
