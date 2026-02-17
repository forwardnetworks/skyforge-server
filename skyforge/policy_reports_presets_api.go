package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type PolicyReportListPresetsRequest struct {
	ForwardNetworkID string `query:"forwardNetworkId" encore:"optional"`
	// NOTE: Encore does not support *bool in query parameters; use tri-state parsing.
	// Accepted: "true" | "false" (case-insensitive). Empty means "any".
	Enabled string `query:"enabled" encore:"optional"`
	Limit   int    `query:"limit" encore:"optional"`
}

// CreateUserPolicyReportPreset creates a saved, scheduled preset.
func (s *Service) CreateUserPolicyReportPreset(ctx context.Context, id string, req *PolicyReportCreatePresetRequest) (*PolicyReportPreset, error) {
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
	out, err := createPolicyReportPreset(ctx, s.db, pc.context.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.preset.create", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetworkID,
		"name":             out.Name,
		"kind":             out.Kind,
		"packId":           out.PackID,
		"enabled":          out.Enabled,
	})
	return out, nil
}

// ListUserPolicyReportPresets lists presets for an owner context (optionally filtered).
func (s *Service) ListUserPolicyReportPresets(ctx context.Context, id string, req *PolicyReportListPresetsRequest) (*PolicyReportListPresetsResponse, error) {
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
	limit := 200
	var enabled *bool
	if req != nil {
		forwardNetworkID = strings.TrimSpace(req.ForwardNetworkID)
		if v := strings.TrimSpace(req.Enabled); v != "" {
			b, parseErr := strconv.ParseBool(v)
			if parseErr != nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid enabled filter").Err()
			}
			enabled = &b
		}
		if req.Limit > 0 {
			limit = req.Limit
		}
	}

	out, err := listPolicyReportPresets(ctx, s.db, pc.context.ID, forwardNetworkID, enabled, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListPresetsResponse{Presets: []PolicyReportPreset{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list presets").Err()
	}
	return &PolicyReportListPresetsResponse{Presets: out}, nil
}

// UpdateUserPolicyReportPreset updates an existing preset.
func (s *Service) UpdateUserPolicyReportPreset(ctx context.Context, id string, presetId string, req *PolicyReportUpdatePresetRequest) (*PolicyReportPreset, error) {
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

	out, err := updatePolicyReportPreset(ctx, s.db, pc.context.ID, pc.claims.Username, presetId, req)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("preset not found").Err()
		}
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.preset.update", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetworkID,
		"name":             out.Name,
		"enabled":          out.Enabled,
	})
	return out, nil
}

// DeleteUserPolicyReportPreset deletes a preset.
func (s *Service) DeleteUserPolicyReportPreset(ctx context.Context, id string, presetId string) (*PolicyReportDecisionResponse, error) {
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

	if err := deletePolicyReportPreset(ctx, s.db, pc.context.ID, presetId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("preset not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete preset").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.preset.delete", map[string]any{
		"id": presetId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}

// RunUserPolicyReportPreset executes the preset immediately and stores a run.
func (s *Service) RunUserPolicyReportPreset(ctx context.Context, id string, presetId string) (*PolicyReportRunPresetResponse, error) {
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

	// Load preset via list helper (simple for demo; bounded by limit).
	presets, err := listPolicyReportPresets(ctx, s.db, pc.context.ID, "", nil, 500)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load preset").Err()
	}
	var preset *PolicyReportPreset
	for i := range presets {
		if strings.TrimSpace(presets[i].ID) == strings.TrimSpace(presetId) {
			preset = &presets[i]
			break
		}
	}
	if preset == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("preset not found").Err()
	}

	var runResp any
	switch strings.ToUpper(strings.TrimSpace(preset.Kind)) {
	case "PACK":
		runResp, err = s.CreateUserPolicyReportRun(ctx, id, &PolicyReportCreateRunRequest{
			ForwardNetworkID: preset.ForwardNetworkID,
			SnapshotID:       preset.SnapshotID,
			PackID:           preset.PackID,
			QueryOptions:     preset.QueryOptions,
			MaxPerCheck:      preset.MaxPerCheck,
			MaxTotal:         preset.MaxTotal,
		})
	case "CUSTOM":
		runResp, err = s.CreateUserPolicyReportCustomRun(ctx, id, &PolicyReportCreateCustomRunRequest{
			ForwardNetworkID: preset.ForwardNetworkID,
			SnapshotID:       preset.SnapshotID,
			PackID:           preset.PackID,
			Title:            preset.TitleTemplate,
			Checks: func() []PolicyReportCustomRunCheckSpec {
				out := make([]PolicyReportCustomRunCheckSpec, 0, len(preset.Checks))
				for _, c := range preset.Checks {
					out = append(out, PolicyReportCustomRunCheckSpec{CheckID: c.CheckID, Parameters: c.Parameters})
				}
				return out
			}(),
			QueryOptions: preset.QueryOptions,
			MaxPerCheck:  preset.MaxPerCheck,
			MaxTotal:     preset.MaxTotal,
		})
	case "PATHS":
		if len(preset.Checks) != 1 || !strings.EqualFold(strings.TrimSpace(preset.Checks[0].CheckID), "paths-enforcement-bypass") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid PATHS preset checks").Err()
		}
		// Decode parameters into the store request shape, then enforce network/snapshot from the preset.
		var storeReq PolicyReportPathsEnforcementBypassStoreRequest
		if b, _ := json.Marshal(preset.Checks[0].Parameters); len(b) > 0 && string(b) != "null" {
			_ = json.Unmarshal(b, &storeReq)
		}
		storeReq.ForwardNetworkID = preset.ForwardNetworkID
		storeReq.SnapshotID = preset.SnapshotID
		storeReq.Title = renderPresetTitle(preset.TitleTemplate, preset.ForwardNetworkID, "paths-assurance", time.Now().UTC())

		runResp, err = s.PostUserPolicyReportPathsEnforcementBypassStore(ctx, id, &storeReq)
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid preset kind").Err()
	}
	if err != nil {
		return nil, err
	}

	switch r := runResp.(type) {
	case *PolicyReportCreateRunResponse:
		return &PolicyReportRunPresetResponse{Preset: *preset, Run: r.Run, Checks: r.Checks, Results: r.Results}, nil
	case *PolicyReportCreateCustomRunResponse:
		return &PolicyReportRunPresetResponse{Preset: *preset, Run: r.Run, Checks: r.Checks, Results: r.Results}, nil
	case *PolicyReportPathsEnforcementBypassStoreResponse:
		return &PolicyReportRunPresetResponse{Preset: *preset, Run: r.Run, Checks: r.Checks, Results: r.Results}, nil
	default:
		return nil, errs.B().Code(errs.Unavailable).Msg("unexpected run response").Err()
	}
}
