package skyforge

import "context"

// GetPolicyReportCatalog returns the embedded Policy Reports catalog for the authenticated user.
//
//encore:api auth method=GET path=/api/policy-reports/catalog
func (s *Service) GetPolicyReportCatalog(ctx context.Context) (*PolicyReportCatalog, error) {
	return s.GetUserPolicyReportCatalog(ctx, personalOwnerRouteKey)
}

// GetPolicyReportPacks returns the embedded Policy Reports packs for the authenticated user.
//
//encore:api auth method=GET path=/api/policy-reports/packs
func (s *Service) GetPolicyReportPacks(ctx context.Context) (*PolicyReportPacks, error) {
	return s.GetUserPolicyReportPacks(ctx, personalOwnerRouteKey)
}

// GetPolicyReportChecks lists checks for the authenticated user.
//
//encore:api auth method=GET path=/api/policy-reports/checks
func (s *Service) GetPolicyReportChecks(ctx context.Context) (*PolicyReportChecksResponse, error) {
	return s.GetUserPolicyReportChecks(ctx, personalOwnerRouteKey)
}

// GetPolicyReportCheck returns one check and its source.
//
//encore:api auth method=GET path=/api/policy-reports/checks/:checkId
func (s *Service) GetPolicyReportCheck(ctx context.Context, checkId string) (*PolicyReportCheckResponse, error) {
	return s.GetUserPolicyReportCheck(ctx, personalOwnerRouteKey, checkId)
}

// GetPolicyReportSnapshots returns available Forward snapshots for policy runs.
//
//encore:api auth method=GET path=/api/policy-reports/snapshots
func (s *Service) GetPolicyReportSnapshots(ctx context.Context, req *PolicyReportSnapshotsRequest) (*PolicyReportSnapshotsResponse, error) {
	return s.GetUserPolicyReportSnapshots(ctx, personalOwnerRouteKey, req)
}

// RunPolicyReportNQE runs ad-hoc NQE against Forward.
//
//encore:api auth method=POST path=/api/policy-reports/nqe
func (s *Service) RunPolicyReportNQE(ctx context.Context, req *PolicyReportNQERequest) (*PolicyReportNQEResponse, error) {
	return s.RunUserPolicyReportNQE(ctx, personalOwnerRouteKey, req)
}

// RunPolicyReportCheck runs a catalog check.
//
//encore:api auth method=POST path=/api/policy-reports/checks/run
func (s *Service) RunPolicyReportCheck(ctx context.Context, req *PolicyReportRunCheckRequest) (*PolicyReportNQEResponse, error) {
	return s.RunUserPolicyReportCheck(ctx, personalOwnerRouteKey, req)
}

// RunPolicyReportPack runs a pack.
//
//encore:api auth method=POST path=/api/policy-reports/packs/run
func (s *Service) RunPolicyReportPack(ctx context.Context, req *PolicyReportRunPackRequest) (*PolicyReportRunPackResponse, error) {
	return s.RunUserPolicyReportPack(ctx, personalOwnerRouteKey, req)
}

// RunPolicyReportPackDelta runs baseline-vs-target pack diff.
//
//encore:api auth method=POST path=/api/policy-reports/packs/delta
func (s *Service) RunPolicyReportPackDelta(ctx context.Context, req *PolicyReportPackDeltaRequest) (*PolicyReportPackDeltaResponse, error) {
	return s.RunUserPolicyReportPackDelta(ctx, personalOwnerRouteKey, req)
}

// SimulatePolicyReportChangePlanning runs change-planning simulation.
//
//encore:api auth method=POST path=/api/policy-reports/change-planning/simulate
func (s *Service) SimulatePolicyReportChangePlanning(ctx context.Context, req *PolicyReportChangePlanningRequest) (*PolicyReportChangePlanningResponse, error) {
	return s.SimulateUserPolicyReportChangePlanning(ctx, personalOwnerRouteKey, req)
}

// CreatePolicyReportRun creates a policy run record.
//
//encore:api auth method=POST path=/api/policy-reports/runs
func (s *Service) CreatePolicyReportRun(ctx context.Context, req *PolicyReportCreateRunRequest) (*PolicyReportCreateRunResponse, error) {
	return s.CreateUserPolicyReportRun(ctx, personalOwnerRouteKey, req)
}

// CreatePolicyReportCustomRun creates a custom policy run.
//
//encore:api auth method=POST path=/api/policy-reports/runs/custom
func (s *Service) CreatePolicyReportCustomRun(ctx context.Context, req *PolicyReportCreateCustomRunRequest) (*PolicyReportCreateCustomRunResponse, error) {
	return s.CreateUserPolicyReportCustomRun(ctx, personalOwnerRouteKey, req)
}

// ListPolicyReportRuns lists policy runs.
//
//encore:api auth method=GET path=/api/policy-reports/runs
func (s *Service) ListPolicyReportRuns(ctx context.Context, req *PolicyReportListRunsRequest) (*PolicyReportListRunsResponse, error) {
	return s.ListUserPolicyReportRuns(ctx, personalOwnerRouteKey, req)
}

// GetPolicyReportRun gets one policy run.
//
//encore:api auth method=GET path=/api/policy-reports/runs/:runId
func (s *Service) GetPolicyReportRun(ctx context.Context, runId string) (*PolicyReportGetRunResponse, error) {
	return s.GetUserPolicyReportRun(ctx, personalOwnerRouteKey, runId)
}

// ListPolicyReportRunFindings lists findings for one run.
//
//encore:api auth method=GET path=/api/policy-reports/runs/:runId/findings
func (s *Service) ListPolicyReportRunFindings(ctx context.Context, runId string, req *PolicyReportListRunFindingsRequest) (*PolicyReportListRunFindingsResponse, error) {
	return s.ListUserPolicyReportRunFindings(ctx, personalOwnerRouteKey, runId, req)
}

// ListPolicyReportFindings lists findings across runs.
//
//encore:api auth method=GET path=/api/policy-reports/findings
func (s *Service) ListPolicyReportFindings(ctx context.Context, req *PolicyReportListFindingsRequest) (*PolicyReportListFindingsResponse, error) {
	return s.ListUserPolicyReportFindings(ctx, personalOwnerRouteKey, req)
}

// GetPolicyReportRunReport returns a rendered report payload.
//
//encore:api auth method=GET path=/api/policy-reports/runs/:runId/report
func (s *Service) GetPolicyReportRunReport(ctx context.Context, runId string, req *PolicyReportRunReportRequest) (*PolicyReportRunReportResponse, error) {
	return s.GetUserPolicyReportRunReport(ctx, personalOwnerRouteKey, runId, req)
}

// CreatePolicyReportRecertCampaign creates a governance campaign.
//
//encore:api auth method=POST path=/api/policy-reports/governance/campaigns
func (s *Service) CreatePolicyReportRecertCampaign(ctx context.Context, req *PolicyReportCreateRecertCampaignRequest) (*PolicyReportRecertCampaignWithCounts, error) {
	return s.CreateUserPolicyReportRecertCampaign(ctx, personalOwnerRouteKey, req)
}

// ListPolicyReportRecertCampaigns lists governance campaigns.
//
//encore:api auth method=GET path=/api/policy-reports/governance/campaigns
func (s *Service) ListPolicyReportRecertCampaigns(ctx context.Context, req *PolicyReportListRecertCampaignsRequest) (*PolicyReportListRecertCampaignsResponse, error) {
	return s.ListUserPolicyReportRecertCampaigns(ctx, personalOwnerRouteKey, req)
}

// GetPolicyReportRecertCampaign returns one governance campaign.
//
//encore:api auth method=GET path=/api/policy-reports/governance/campaigns/:campaignId
func (s *Service) GetPolicyReportRecertCampaign(ctx context.Context, campaignId string) (*PolicyReportRecertCampaignWithCounts, error) {
	return s.GetUserPolicyReportRecertCampaign(ctx, personalOwnerRouteKey, campaignId)
}

// GeneratePolicyReportRecertAssignments creates assignments for a campaign.
//
//encore:api auth method=POST path=/api/policy-reports/governance/campaigns/:campaignId/generate
func (s *Service) GeneratePolicyReportRecertAssignments(ctx context.Context, campaignId string, req *PolicyReportGenerateRecertAssignmentsRequest) (*PolicyReportGenerateRecertAssignmentsResponse, error) {
	return s.GenerateUserPolicyReportRecertAssignments(ctx, personalOwnerRouteKey, campaignId, req)
}

// ListPolicyReportRecertAssignments lists governance assignments.
//
//encore:api auth method=GET path=/api/policy-reports/governance/assignments
func (s *Service) ListPolicyReportRecertAssignments(ctx context.Context, req *PolicyReportListRecertAssignmentsRequest) (*PolicyReportListRecertAssignmentsResponse, error) {
	return s.ListUserPolicyReportRecertAssignments(ctx, personalOwnerRouteKey, req)
}

// AttestPolicyReportRecertAssignment attests one assignment.
//
//encore:api auth method=POST path=/api/policy-reports/governance/assignments/:assignmentId/attest
func (s *Service) AttestPolicyReportRecertAssignment(ctx context.Context, assignmentId string, req *PolicyReportAttestAssignmentRequest) (*PolicyReportDecisionResponse, error) {
	return s.AttestUserPolicyReportRecertAssignment(ctx, personalOwnerRouteKey, assignmentId, req)
}

// WaivePolicyReportRecertAssignment waives one assignment.
//
//encore:api auth method=POST path=/api/policy-reports/governance/assignments/:assignmentId/waive
func (s *Service) WaivePolicyReportRecertAssignment(ctx context.Context, assignmentId string, req *PolicyReportAttestAssignmentRequest) (*PolicyReportDecisionResponse, error) {
	return s.WaiveUserPolicyReportRecertAssignment(ctx, personalOwnerRouteKey, assignmentId, req)
}

// CreatePolicyReportException creates a governance exception.
//
//encore:api auth method=POST path=/api/policy-reports/governance/exceptions
func (s *Service) CreatePolicyReportException(ctx context.Context, req *PolicyReportCreateExceptionRequest) (*PolicyReportException, error) {
	return s.CreateUserPolicyReportException(ctx, personalOwnerRouteKey, req)
}

// ListPolicyReportExceptions lists governance exceptions.
//
//encore:api auth method=GET path=/api/policy-reports/governance/exceptions
func (s *Service) ListPolicyReportExceptions(ctx context.Context, req *PolicyReportListExceptionsRequest) (*PolicyReportListExceptionsResponse, error) {
	return s.ListUserPolicyReportExceptions(ctx, personalOwnerRouteKey, req)
}

// ApprovePolicyReportException approves one exception.
//
//encore:api auth method=POST path=/api/policy-reports/governance/exceptions/:exceptionId/approve
func (s *Service) ApprovePolicyReportException(ctx context.Context, exceptionId string) (*PolicyReportDecisionResponse, error) {
	return s.ApproveUserPolicyReportException(ctx, personalOwnerRouteKey, exceptionId)
}

// RejectPolicyReportException rejects one exception.
//
//encore:api auth method=POST path=/api/policy-reports/governance/exceptions/:exceptionId/reject
func (s *Service) RejectPolicyReportException(ctx context.Context, exceptionId string) (*PolicyReportDecisionResponse, error) {
	return s.RejectUserPolicyReportException(ctx, personalOwnerRouteKey, exceptionId)
}

// PostPolicyReportPathsEnforcementBypass evaluates bypass queries.
//
//encore:api auth method=POST path=/api/policy-reports/paths/enforcement-bypass
func (s *Service) PostPolicyReportPathsEnforcementBypass(ctx context.Context, req *PolicyReportPathsEnforcementBypassRequest) (*PolicyReportNQEResponse, error) {
	return s.PostUserPolicyReportPathsEnforcementBypass(ctx, personalOwnerRouteKey, req)
}

// PostPolicyReportPathsEnforcementBypassStore stores bypass query results.
//
//encore:api auth method=POST path=/api/policy-reports/paths/enforcement-bypass/store
func (s *Service) PostPolicyReportPathsEnforcementBypassStore(ctx context.Context, req *PolicyReportPathsEnforcementBypassStoreRequest) (*PolicyReportPathsEnforcementBypassStoreResponse, error) {
	return s.PostUserPolicyReportPathsEnforcementBypassStore(ctx, personalOwnerRouteKey, req)
}

// CreatePolicyReportForwardNetwork links a Forward network.
//
//encore:api auth method=POST path=/api/policy-reports/networks
func (s *Service) CreatePolicyReportForwardNetwork(ctx context.Context, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	return s.CreateUserPolicyReportForwardNetwork(ctx, personalOwnerRouteKey, req)
}

// ListPolicyReportForwardNetworks lists linked Forward networks.
//
//encore:api auth method=GET path=/api/policy-reports/networks
func (s *Service) ListPolicyReportForwardNetworks(ctx context.Context) (*PolicyReportListForwardNetworksResponse, error) {
	return s.ListUserPolicyReportForwardNetworks(ctx, personalOwnerRouteKey)
}

// DeletePolicyReportForwardNetwork removes a linked Forward network.
//
//encore:api auth method=DELETE path=/api/policy-reports/networks/:networkRef
func (s *Service) DeletePolicyReportForwardNetwork(ctx context.Context, networkRef string) (*PolicyReportDecisionResponse, error) {
	return s.DeleteUserPolicyReportForwardNetwork(ctx, personalOwnerRouteKey, networkRef)
}

// GetPolicyReportForwardNetworkCredentials returns credential status for a linked network.
//
//encore:api auth method=GET path=/api/policy-reports/networks/:forwardNetworkId/credentials
func (s *Service) GetPolicyReportForwardNetworkCredentials(ctx context.Context, forwardNetworkId string) (*PolicyReportForwardCredentialsStatus, error) {
	return s.GetUserPolicyReportForwardNetworkCredentials(ctx, personalOwnerRouteKey, forwardNetworkId)
}

// PutPolicyReportForwardNetworkCredentials upserts credential mapping for a linked network.
//
//encore:api auth method=PUT path=/api/policy-reports/networks/:forwardNetworkId/credentials
func (s *Service) PutPolicyReportForwardNetworkCredentials(ctx context.Context, forwardNetworkId string, req *PolicyReportPutForwardCredentialsRequest) (*PolicyReportForwardCredentialsStatus, error) {
	return s.PutUserPolicyReportForwardNetworkCredentials(ctx, personalOwnerRouteKey, forwardNetworkId, req)
}

// DeletePolicyReportForwardNetworkCredentials clears credential mapping for a linked network.
//
//encore:api auth method=DELETE path=/api/policy-reports/networks/:forwardNetworkId/credentials
func (s *Service) DeletePolicyReportForwardNetworkCredentials(ctx context.Context, forwardNetworkId string) (*PolicyReportDecisionResponse, error) {
	return s.DeleteUserPolicyReportForwardNetworkCredentials(ctx, personalOwnerRouteKey, forwardNetworkId)
}

// CreatePolicyReportZone creates a zone for a linked network.
//
//encore:api auth method=POST path=/api/policy-reports/networks/:forwardNetworkId/zones
func (s *Service) CreatePolicyReportZone(ctx context.Context, forwardNetworkId string, req *PolicyReportCreateZoneRequest) (*PolicyReportZone, error) {
	return s.CreateUserPolicyReportZone(ctx, personalOwnerRouteKey, forwardNetworkId, req)
}

// ListPolicyReportZones lists zones for a linked network.
//
//encore:api auth method=GET path=/api/policy-reports/networks/:forwardNetworkId/zones
func (s *Service) ListPolicyReportZones(ctx context.Context, forwardNetworkId string) (*PolicyReportListZonesResponse, error) {
	return s.ListUserPolicyReportZones(ctx, personalOwnerRouteKey, forwardNetworkId)
}

// UpdatePolicyReportZone updates a zone for a linked network.
//
//encore:api auth method=PUT path=/api/policy-reports/networks/:forwardNetworkId/zones/:zoneId
func (s *Service) UpdatePolicyReportZone(ctx context.Context, forwardNetworkId, zoneId string, req *PolicyReportUpdateZoneRequest) (*PolicyReportZone, error) {
	return s.UpdateUserPolicyReportZone(ctx, personalOwnerRouteKey, forwardNetworkId, zoneId, req)
}

// DeletePolicyReportZone deletes a zone for a linked network.
//
//encore:api auth method=DELETE path=/api/policy-reports/networks/:forwardNetworkId/zones/:zoneId
func (s *Service) DeletePolicyReportZone(ctx context.Context, forwardNetworkId, zoneId string) (*PolicyReportDecisionResponse, error) {
	return s.DeleteUserPolicyReportZone(ctx, personalOwnerRouteKey, forwardNetworkId, zoneId)
}

// CreatePolicyReportPreset creates a report preset.
//
//encore:api auth method=POST path=/api/policy-reports/presets
func (s *Service) CreatePolicyReportPreset(ctx context.Context, req *PolicyReportCreatePresetRequest) (*PolicyReportPreset, error) {
	return s.CreateUserPolicyReportPreset(ctx, personalOwnerRouteKey, req)
}

// ListPolicyReportPresets lists report presets.
//
//encore:api auth method=GET path=/api/policy-reports/presets
func (s *Service) ListPolicyReportPresets(ctx context.Context, req *PolicyReportListPresetsRequest) (*PolicyReportListPresetsResponse, error) {
	return s.ListUserPolicyReportPresets(ctx, personalOwnerRouteKey, req)
}

// UpdatePolicyReportPreset updates a report preset.
//
//encore:api auth method=PUT path=/api/policy-reports/presets/:presetId
func (s *Service) UpdatePolicyReportPreset(ctx context.Context, presetId string, req *PolicyReportUpdatePresetRequest) (*PolicyReportPreset, error) {
	return s.UpdateUserPolicyReportPreset(ctx, personalOwnerRouteKey, presetId, req)
}

// DeletePolicyReportPreset deletes a report preset.
//
//encore:api auth method=DELETE path=/api/policy-reports/presets/:presetId
func (s *Service) DeletePolicyReportPreset(ctx context.Context, presetId string) (*PolicyReportDecisionResponse, error) {
	return s.DeleteUserPolicyReportPreset(ctx, personalOwnerRouteKey, presetId)
}

// RunPolicyReportPreset executes a report preset.
//
//encore:api auth method=POST path=/api/policy-reports/presets/:presetId/run
func (s *Service) RunPolicyReportPreset(ctx context.Context, presetId string) (*PolicyReportRunPresetResponse, error) {
	return s.RunUserPolicyReportPreset(ctx, personalOwnerRouteKey, presetId)
}
