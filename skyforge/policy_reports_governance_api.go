package skyforge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"encore.dev/beta/errs"
)

func requireUserEditor(pc *ownerContext) error {
	if pc == nil {
		return errs.B().Code(errs.Unavailable).Msg("user context unavailable").Err()
	}
	switch pc.access {
	case "admin", "owner", "editor":
		return nil
	case "viewer":
		return errs.B().Code(errs.PermissionDenied).Msg("read-only access").Err()
	default:
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
}

func requireUserOwnerRole(pc *ownerContext) error {
	if pc == nil {
		return errs.B().Code(errs.Unavailable).Msg("user context unavailable").Err()
	}
	switch pc.access {
	case "admin", "owner":
		return nil
	default:
		return errs.B().Code(errs.PermissionDenied).Msg("owner access required").Err()
	}
}

// CreateUserPolicyReportRecertCampaign creates a recertification campaign for a given Forward network/snapshot/pack.
func (s *Service) CreateUserPolicyReportRecertCampaign(ctx context.Context, id string, req *PolicyReportCreateRecertCampaignRequest) (*PolicyReportRecertCampaignWithCounts, error) {
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

	// Validate pack exists (helps users avoid creating a broken campaign).
	packs, err := loadPolicyReportPacks()
	if err != nil || packs == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("packs unavailable").Err()
	}
	packID := strings.TrimSpace(req.PackID)
	found := false
	for _, p := range packs.Packs {
		if strings.EqualFold(strings.TrimSpace(p.ID), packID) {
			found = true
			break
		}
	}
	if !found {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown packId").Err()
	}

	c, err := createPolicyReportRecertCampaign(ctx, s.db, pc.context.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.recert_campaign.create", map[string]any{
		"campaignId":    c.ID,
		"packId":        c.PackID,
		"networkId":     c.ForwardNetwork,
		"snapshotId":    c.SnapshotID,
		"name":          c.Name,
		"ownerUsername": pc.context.ID,
	})
	return &PolicyReportRecertCampaignWithCounts{Campaign: *c, Counts: PolicyReportRecertCampaignCounts{}}, nil
}

// ListUserPolicyReportRecertCampaigns lists recertification campaigns.
func (s *Service) ListUserPolicyReportRecertCampaigns(ctx context.Context, id string, req *PolicyReportListRecertCampaignsRequest) (*PolicyReportListRecertCampaignsResponse, error) {
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
	campaigns, err := listPolicyReportRecertCampaigns(ctx, s.db, pc.context.ID, req)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListRecertCampaignsResponse{Campaigns: []PolicyReportRecertCampaignWithCounts{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list campaigns").Err()
	}
	return &PolicyReportListRecertCampaignsResponse{Campaigns: campaigns}, nil
}

// GetUserPolicyReportRecertCampaign gets one campaign plus assignment counts.
func (s *Service) GetUserPolicyReportRecertCampaign(ctx context.Context, id string, campaignId string) (*PolicyReportRecertCampaignWithCounts, error) {
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
	out, err := getPolicyReportRecertCampaign(ctx, s.db, pc.context.ID, campaignId)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("campaign not found").Err()
	}
	return out, nil
}

// GenerateUserPolicyReportRecertAssignments runs the campaign pack and stores resulting findings as assignments.
func (s *Service) GenerateUserPolicyReportRecertAssignments(ctx context.Context, id string, campaignId string, req *PolicyReportGenerateRecertAssignmentsRequest) (*PolicyReportGenerateRecertAssignmentsResponse, error) {
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

	c, err := getPolicyReportRecertCampaign(ctx, s.db, pc.context.ID, campaignId)
	if err != nil || c == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("campaign not found").Err()
	}
	campaign := c.Campaign

	packs, err := loadPolicyReportPacks()
	if err != nil || packs == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("packs unavailable").Err()
	}
	var pack *PolicyReportPack
	for i := range packs.Packs {
		if strings.EqualFold(strings.TrimSpace(packs.Packs[i].ID), strings.TrimSpace(campaign.PackID)) {
			pack = &packs.Packs[i]
			break
		}
	}
	if pack == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("campaign pack missing").Err()
	}

	assignee := ""
	maxPerCheck := 500
	maxTotal := 5000
	var queryOptions JSONMap
	if req != nil {
		assignee = strings.TrimSpace(req.AssigneeUsername)
		if req.MaxPerCheck > 0 {
			maxPerCheck = req.MaxPerCheck
		}
		if req.MaxTotal > 0 {
			maxTotal = req.MaxTotal
		}
		queryOptions = req.QueryOptions
	}
	if maxPerCheck <= 0 || maxPerCheck > 20_000 {
		maxPerCheck = 500
	}
	if maxTotal <= 0 || maxTotal > 200_000 {
		maxTotal = 5000
	}

	fwdClient, err := s.policyReportsForwardClient(ctx, pc.context.ID, pc.claims.Username, strings.TrimSpace(campaign.ForwardNetwork))
	if err != nil {
		return nil, err
	}

	var assignments []PolicyReportRecertAssignment
	total := 0
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
		query.Set("networkId", strings.TrimSpace(campaign.ForwardNetwork))
		if v := strings.TrimSpace(campaign.SnapshotID); v != "" {
			query.Set("snapshotId", v)
		}
		payload := map[string]any{"query": queryText}
		if len(params) > 0 {
			payload["parameters"] = params
		}
		if queryOptions != nil {
			payload["queryOptions"] = queryOptions
		}

		resp, body, err := fwdClient.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Meta("checkId", checkID).Err()
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("checkId", checkID).Meta("upstream", strings.TrimSpace(string(body))).Err()
		}

		nqeResp, err := policyReportsNormalizeNQEResponseForCheck(checkID, body)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Meta("checkId", checkID).Err()
		}

		var items []json.RawMessage
		_ = json.Unmarshal(nqeResp.Results, &items)
		if len(items) > maxPerCheck {
			items = items[:maxPerCheck]
		}
		for _, it := range items {
			if total >= maxTotal {
				break
			}
			fid := policyReportsExtractFindingID(it)
			if fid == "" {
				fid = policyReportsComputeFindingID(checkID, it)
			}
			assignments = append(assignments, PolicyReportRecertAssignment{
				FindingID: fid,
				CheckID:   checkID,
				Finding:   it,
			})
			total++
		}
		if total >= maxTotal {
			break
		}
	}

	created, err := replacePolicyReportRecertAssignments(ctx, s.db, pc.context.ID, campaign.ID, assignee, assignments)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store assignments").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.recert_campaign.generate", map[string]any{
		"campaignId": campaign.ID,
		"packId":     campaign.PackID,
		"created":    created,
		"maxTotal":   maxTotal,
		"maxPer":     maxPerCheck,
	})
	return &PolicyReportGenerateRecertAssignmentsResponse{CampaignID: campaign.ID, Created: created}, nil
}

// ListUserPolicyReportRecertAssignments lists assignments.
func (s *Service) ListUserPolicyReportRecertAssignments(ctx context.Context, id string, req *PolicyReportListRecertAssignmentsRequest) (*PolicyReportListRecertAssignmentsResponse, error) {
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
	out, err := listPolicyReportRecertAssignments(ctx, s.db, pc.context.ID, req)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListRecertAssignmentsResponse{Assignments: []PolicyReportRecertAssignment{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list assignments").Err()
	}
	return &PolicyReportListRecertAssignmentsResponse{Assignments: out}, nil
}

// AttestUserPolicyReportRecertAssignment marks an assignment as attested.
func (s *Service) AttestUserPolicyReportRecertAssignment(ctx context.Context, id string, assignmentId string, req *PolicyReportAttestAssignmentRequest) (*PolicyReportDecisionResponse, error) {
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
	just := ""
	if req != nil {
		just = req.Justification
	}
	if err := updatePolicyReportAssignmentStatus(ctx, s.db, pc.context.ID, assignmentId, "ATTESTED", just); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update assignment").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.assignment.attest", map[string]any{
		"assignmentId": assignmentId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}

// WaiveUserPolicyReportRecertAssignment marks an assignment as waived.
func (s *Service) WaiveUserPolicyReportRecertAssignment(ctx context.Context, id string, assignmentId string, req *PolicyReportAttestAssignmentRequest) (*PolicyReportDecisionResponse, error) {
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
	just := ""
	if req != nil {
		just = req.Justification
	}
	if err := updatePolicyReportAssignmentStatus(ctx, s.db, pc.context.ID, assignmentId, "WAIVED", just); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update assignment").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.assignment.waive", map[string]any{
		"assignmentId": assignmentId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}

// CreateUserPolicyReportException proposes an exception for a finding.
func (s *Service) CreateUserPolicyReportException(ctx context.Context, id string, req *PolicyReportCreateExceptionRequest) (*PolicyReportException, error) {
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
	out, err := createPolicyReportException(ctx, s.db, pc.context.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.exception.propose", map[string]any{
		"exceptionId": out.ID,
		"findingId":   out.FindingID,
		"checkId":     out.CheckID,
		"networkId":   out.ForwardNetwork,
	})
	return out, nil
}

// ListUserPolicyReportExceptions lists exceptions.
func (s *Service) ListUserPolicyReportExceptions(ctx context.Context, id string, req *PolicyReportListExceptionsRequest) (*PolicyReportListExceptionsResponse, error) {
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
	out, err := listPolicyReportExceptions(ctx, s.db, pc.context.ID, req)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListExceptionsResponse{Exceptions: []PolicyReportException{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list exceptions").Err()
	}
	return &PolicyReportListExceptionsResponse{Exceptions: out}, nil
}

// ApproveUserPolicyReportException approves an exception (owner/admin only).
func (s *Service) ApproveUserPolicyReportException(ctx context.Context, id string, exceptionId string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserOwnerRole(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if err := updatePolicyReportExceptionStatus(ctx, s.db, pc.context.ID, exceptionId, pc.claims.Username, "APPROVED"); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update exception").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.exception.approve", map[string]any{
		"exceptionId": exceptionId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}

// RejectUserPolicyReportException rejects an exception (owner/admin only).
func (s *Service) RejectUserPolicyReportException(ctx context.Context, id string, exceptionId string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserOwnerRole(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if err := updatePolicyReportExceptionStatus(ctx, s.db, pc.context.ID, exceptionId, pc.claims.Username, "REJECTED"); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update exception").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.exception.reject", map[string]any{
		"exceptionId": exceptionId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
