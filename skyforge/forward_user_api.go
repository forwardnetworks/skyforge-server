package skyforge

import "context"

// GetForwardConfig returns the authenticated user's Forward integration config.
//
//encore:api auth method=GET path=/api/integrations/forward
func (s *Service) GetForwardConfig(ctx context.Context) (*UserForwardConfigResponse, error) {
	return s.GetUserForwardConfig(ctx, personalOwnerRouteKey)
}

// PutForwardConfig updates the authenticated user's Forward integration config.
//
//encore:api auth method=PUT path=/api/integrations/forward
func (s *Service) PutForwardConfig(ctx context.Context, req *UserForwardConfigRequest) (*UserForwardConfigResponse, error) {
	return s.PutUserForwardConfig(ctx, personalOwnerRouteKey, req)
}

// PostForwardConfig stores the authenticated user's Forward integration config.
//
//encore:api auth method=POST path=/api/integrations/forward
func (s *Service) PostForwardConfig(ctx context.Context, req *UserForwardConfigRequest) (*UserForwardConfigResponse, error) {
	return s.PostUserForwardConfig(ctx, personalOwnerRouteKey, req)
}

// DeleteForwardConfig removes the authenticated user's Forward integration config.
//
//encore:api auth method=DELETE path=/api/integrations/forward
func (s *Service) DeleteForwardConfig(ctx context.Context) (*UserForwardConfigResponse, error) {
	return s.DeleteUserForwardConfig(ctx, personalOwnerRouteKey)
}

// ListForwardCollectors lists collectors from the configured Forward instance.
//
//encore:api auth method=GET path=/api/integrations/forward/collectors
func (s *Service) ListForwardIntegrationCollectorsUser(ctx context.Context) (*UserForwardCollectorsResponse, error) {
	return s.GetUserForwardCollectors(ctx, personalOwnerRouteKey)
}

// CreateForwardCollector creates a collector in the configured Forward instance.
//
//encore:api auth method=POST path=/api/integrations/forward/collectors
func (s *Service) CreateForwardIntegrationCollectorUser(ctx context.Context) (*UserForwardCollectorCreateResponse, error) {
	return s.CreateUserForwardCollector(ctx, personalOwnerRouteKey)
}

// ApplyForwardCredentialSet applies a user-owned Forward credential set to active Forward integration config.
//
//encore:api auth method=POST path=/api/integrations/forward/apply-credential-set
func (s *Service) ApplyForwardCredentialSet(ctx context.Context, req *ApplyUserForwardCredentialSetRequest) (*UserForwardConfigResponse, error) {
	return s.ApplyUserForwardCredentialSet(ctx, personalOwnerRouteKey, req)
}

// GetForwardNetworkCapacitySummaryUser returns capacity summary for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/summary
func (s *Service) GetForwardNetworkCapacitySummaryUser(ctx context.Context, networkRef string) (*ForwardNetworkCapacitySummaryResponse, error) {
	return s.GetUserForwardNetworkCapacitySummary(ctx, personalOwnerRouteKey, networkRef)
}

// RefreshForwardNetworkCapacityRollupsUser refreshes capacity rollups for a Forward network.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/capacity/rollups/refresh
func (s *Service) RefreshForwardNetworkCapacityRollupsUser(ctx context.Context, networkRef string) (*ForwardNetworkCapacityRefreshResponse, error) {
	return s.RefreshUserForwardNetworkCapacityRollups(ctx, personalOwnerRouteKey, networkRef)
}

// GetForwardNetworkCapacityInventoryUser returns capacity inventory for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/inventory
func (s *Service) GetForwardNetworkCapacityInventoryUser(ctx context.Context, networkRef string) (*ForwardNetworkCapacityInventoryResponse, error) {
	return s.GetUserForwardNetworkCapacityInventory(ctx, personalOwnerRouteKey, networkRef)
}

// GetForwardNetworkCapacityGrowthUser returns growth trend data for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/growth
func (s *Service) GetForwardNetworkCapacityGrowthUser(ctx context.Context, networkRef string, q *DeploymentCapacityGrowthQuery) (*ForwardNetworkCapacityGrowthResponse, error) {
	return s.GetUserForwardNetworkCapacityGrowth(ctx, personalOwnerRouteKey, networkRef, q)
}

// GetForwardNetworkCapacityInterfaceMetricsUser returns current interface metrics proxy payload.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/perf/interface-metrics
func (s *Service) GetForwardNetworkCapacityInterfaceMetricsUser(ctx context.Context, networkRef string, q *CapacityInterfaceMetricsQuery) (*CapacityPerfProxyResponse, error) {
	return s.GetUserForwardNetworkCapacityInterfaceMetrics(ctx, personalOwnerRouteKey, networkRef, q)
}

// PostForwardNetworkCapacityInterfaceMetricsHistoryUser returns interface metrics history proxy payload.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/capacity/perf/interface-metrics-history
func (s *Service) PostForwardNetworkCapacityInterfaceMetricsHistoryUser(ctx context.Context, networkRef string, req *capacityInterfaceMetricsHistoryRequest) (*CapacityPerfProxyResponse, error) {
	return s.PostUserForwardNetworkCapacityInterfaceMetricsHistory(ctx, personalOwnerRouteKey, networkRef, req)
}

// PostForwardNetworkCapacityDeviceMetricsHistoryUser returns device metrics history proxy payload.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/capacity/perf/device-metrics-history
func (s *Service) PostForwardNetworkCapacityDeviceMetricsHistoryUser(ctx context.Context, networkRef string, req *capacityDeviceSet) (*CapacityPerfProxyResponse, error) {
	return s.PostUserForwardNetworkCapacityDeviceMetricsHistory(ctx, personalOwnerRouteKey, networkRef, req)
}

// GetForwardNetworkCapacityUnhealthyDevicesUser returns unhealthy devices proxy payload.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/perf/unhealthy-devices
func (s *Service) GetForwardNetworkCapacityUnhealthyDevicesUser(ctx context.Context, networkRef string, q *CapacityUnhealthyDevicesQuery) (*CapacityPerfProxyResponse, error) {
	return s.GetUserForwardNetworkCapacityUnhealthyDevices(ctx, personalOwnerRouteKey, networkRef, q)
}

// PostForwardNetworkCapacityUnhealthyInterfacesUser returns unhealthy interfaces proxy payload.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/capacity/perf/unhealthy-interfaces
func (s *Service) PostForwardNetworkCapacityUnhealthyInterfacesUser(ctx context.Context, networkRef string, req *CapacityUnhealthyInterfacesRequest) (*CapacityPerfProxyResponse, error) {
	return s.PostUserForwardNetworkCapacityUnhealthyInterfaces(ctx, personalOwnerRouteKey, networkRef, req)
}

// GetForwardNetworkCapacityCoverageUser returns coverage summary for path-bottleneck/capacity sources.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/coverage
func (s *Service) GetForwardNetworkCapacityCoverageUser(ctx context.Context, networkRef string) (*ForwardNetworkCapacityCoverageResponse, error) {
	return s.GetUserForwardNetworkCapacityCoverage(ctx, personalOwnerRouteKey, networkRef)
}

// PostForwardNetworkCapacityPathBottlenecksUser evaluates path bottlenecks for one or more paths.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/capacity/path-bottlenecks
func (s *Service) PostForwardNetworkCapacityPathBottlenecksUser(ctx context.Context, networkRef string, req *ForwardNetworkCapacityPathBottlenecksRequest) (*ForwardNetworkCapacityPathBottlenecksResponse, error) {
	return s.PostUserForwardNetworkCapacityPathBottlenecks(ctx, personalOwnerRouteKey, networkRef, req)
}

// GetForwardNetworkCapacityPortfolioUser returns portfolio stats across user's Forward networks.
//
//encore:api auth method=GET path=/api/capacity/fwd/portfolio
func (s *Service) GetForwardNetworkCapacityPortfolioUser(ctx context.Context) (*ForwardNetworkCapacityPortfolioResponse, error) {
	return s.GetUserForwardNetworkCapacityPortfolio(ctx, personalOwnerRouteKey)
}

// GetForwardNetworkCapacitySnapshotDeltaUser returns snapshot delta details for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/snapshot-delta
func (s *Service) GetForwardNetworkCapacitySnapshotDeltaUser(ctx context.Context, networkRef string) (*ForwardNetworkCapacitySnapshotDeltaResponse, error) {
	return s.GetUserForwardNetworkCapacitySnapshotDelta(ctx, personalOwnerRouteKey, networkRef)
}

// GetForwardNetworkCapacityUpgradeCandidatesUser returns upgrade candidates for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/capacity/upgrade-candidates
func (s *Service) GetForwardNetworkCapacityUpgradeCandidatesUser(ctx context.Context, networkRef string, q *ForwardNetworkCapacityUpgradeCandidatesQuery) (*ForwardNetworkCapacityUpgradeCandidatesResponse, error) {
	return s.GetUserForwardNetworkCapacityUpgradeCandidates(ctx, personalOwnerRouteKey, networkRef, q)
}

// GetForwardNetworkAssuranceSummaryUser returns assurance summary for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/assurance/summary
func (s *Service) GetForwardNetworkAssuranceSummaryUser(ctx context.Context, networkRef string, params *ForwardAssuranceSummaryParams) (*ForwardAssuranceSummaryResponse, error) {
	return s.GetUserForwardNetworkAssuranceSummary(ctx, personalOwnerRouteKey, networkRef, params)
}

// RefreshForwardNetworkAssuranceUser refreshes assurance summary for a Forward network.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/refresh
func (s *Service) RefreshForwardNetworkAssuranceUser(ctx context.Context, networkRef string) (*ForwardAssuranceSummaryResponse, error) {
	return s.RefreshUserForwardNetworkAssurance(ctx, personalOwnerRouteKey, networkRef)
}

// SeedForwardNetworkAssuranceDemoUser seeds demo assurance entities for a Forward network.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/demo/seed
func (s *Service) SeedForwardNetworkAssuranceDemoUser(ctx context.Context, networkRef string) (*ForwardAssuranceDemoSeedResponse, error) {
	return s.SeedUserForwardNetworkAssuranceDemo(ctx, personalOwnerRouteKey, networkRef)
}

// ListForwardNetworkAssuranceSummaryHistoryUser returns assurance summary history.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/assurance/summary/history
func (s *Service) ListForwardNetworkAssuranceSummaryHistoryUser(ctx context.Context, networkRef string, params *ForwardAssuranceHistoryParams) (*ForwardAssuranceHistoryResponse, error) {
	return s.ListUserForwardNetworkAssuranceSummaryHistory(ctx, personalOwnerRouteKey, networkRef, params)
}

// ListForwardNetworkAssuranceStudioScenariosUser lists assurance studio scenarios.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/assurance/studio/scenarios
func (s *Service) ListForwardNetworkAssuranceStudioScenariosUser(ctx context.Context, networkRef string) (*AssuranceStudioListScenariosResponse, error) {
	return s.ListUserForwardNetworkAssuranceStudioScenarios(ctx, personalOwnerRouteKey, networkRef)
}

// CreateForwardNetworkAssuranceStudioScenarioUser creates an assurance studio scenario.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/studio/scenarios
func (s *Service) CreateForwardNetworkAssuranceStudioScenarioUser(ctx context.Context, networkRef string, req *AssuranceStudioCreateScenarioRequest) (*AssuranceStudioScenario, error) {
	return s.CreateUserForwardNetworkAssuranceStudioScenario(ctx, personalOwnerRouteKey, networkRef, req)
}

// GetForwardNetworkAssuranceStudioScenarioUser fetches a scenario.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/assurance/studio/scenarios/:scenarioId
func (s *Service) GetForwardNetworkAssuranceStudioScenarioUser(ctx context.Context, networkRef, scenarioId string) (*AssuranceStudioScenario, error) {
	return s.GetUserForwardNetworkAssuranceStudioScenario(ctx, personalOwnerRouteKey, networkRef, scenarioId)
}

// UpdateForwardNetworkAssuranceStudioScenarioUser updates a scenario.
//
//encore:api auth method=PUT path=/api/fwd/:networkRef/assurance/studio/scenarios/:scenarioId
func (s *Service) UpdateForwardNetworkAssuranceStudioScenarioUser(ctx context.Context, networkRef, scenarioId string, req *AssuranceStudioUpdateScenarioRequest) (*AssuranceStudioScenario, error) {
	return s.UpdateUserForwardNetworkAssuranceStudioScenario(ctx, personalOwnerRouteKey, networkRef, scenarioId, req)
}

// DeleteForwardNetworkAssuranceStudioScenarioUser deletes a scenario.
//
//encore:api auth method=DELETE path=/api/fwd/:networkRef/assurance/studio/scenarios/:scenarioId
func (s *Service) DeleteForwardNetworkAssuranceStudioScenarioUser(ctx context.Context, networkRef, scenarioId string) (*PolicyReportDecisionResponse, error) {
	return s.DeleteUserForwardNetworkAssuranceStudioScenario(ctx, personalOwnerRouteKey, networkRef, scenarioId)
}

// ListForwardNetworkAssuranceStudioRunsUser lists scenario runs.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/assurance/studio/runs
func (s *Service) ListForwardNetworkAssuranceStudioRunsUser(ctx context.Context, networkRef string) (*AssuranceStudioListRunsResponse, error) {
	return s.ListUserForwardNetworkAssuranceStudioRuns(ctx, personalOwnerRouteKey, networkRef)
}

// CreateForwardNetworkAssuranceStudioRunUser creates a scenario run.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/studio/runs
func (s *Service) CreateForwardNetworkAssuranceStudioRunUser(ctx context.Context, networkRef string, req *AssuranceStudioCreateRunRequest) (*AssuranceStudioRun, error) {
	return s.CreateUserForwardNetworkAssuranceStudioRun(ctx, personalOwnerRouteKey, networkRef, req)
}

// GetForwardNetworkAssuranceStudioRunUser fetches a scenario run by id.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/assurance/studio/runs/:runId
func (s *Service) GetForwardNetworkAssuranceStudioRunUser(ctx context.Context, networkRef, runId string) (*AssuranceStudioRunDetail, error) {
	return s.GetUserForwardNetworkAssuranceStudioRun(ctx, personalOwnerRouteKey, networkRef, runId)
}

// PostForwardNetworkAssuranceStudioEvaluateUser evaluates ad-hoc NQE checks.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/studio/evaluate
func (s *Service) PostForwardNetworkAssuranceStudioEvaluateUser(ctx context.Context, networkRef string, req *AssuranceStudioEvaluateRequest) (*AssuranceStudioEvaluateResponse, error) {
	return s.PostUserForwardNetworkAssuranceStudioEvaluate(ctx, personalOwnerRouteKey, networkRef, req)
}

// PostForwardNetworkAssuranceTrafficSeedsUser creates traffic scenario seed data.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/traffic/seeds
func (s *Service) PostForwardNetworkAssuranceTrafficSeedsUser(ctx context.Context, networkRef string, req *AssuranceTrafficSeedRequest) (*AssuranceTrafficSeedResponse, error) {
	return s.PostUserForwardNetworkAssuranceTrafficSeeds(ctx, personalOwnerRouteKey, networkRef, req)
}

// PostForwardNetworkAssuranceTrafficEvaluateUser evaluates traffic scenarios.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/assurance/traffic/evaluate
func (s *Service) PostForwardNetworkAssuranceTrafficEvaluateUser(ctx context.Context, networkRef string, req *AssuranceTrafficEvaluateRequest) (*AssuranceTrafficEvaluateResponse, error) {
	return s.PostUserForwardNetworkAssuranceTrafficEvaluate(ctx, personalOwnerRouteKey, networkRef, req)
}

// GetForwardNetworkMetricsSummaryUser returns SNMP/perf summary for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/metrics/summary
func (s *Service) GetForwardNetworkMetricsSummaryUser(ctx context.Context, networkRef string) (*ForwardMetricsSummaryResponse, error) {
	return s.GetUserForwardNetworkMetricsSummary(ctx, personalOwnerRouteKey, networkRef)
}

// GetForwardNetworkMetricsHistoryUser returns metrics history for a Forward network.
//
//encore:api auth method=GET path=/api/fwd/:networkRef/metrics/history
func (s *Service) GetForwardNetworkMetricsHistoryUser(ctx context.Context, networkRef string, q *ForwardMetricsHistoryQuery) (*ForwardMetricsHistoryResponse, error) {
	return s.GetUserForwardNetworkMetricsHistory(ctx, personalOwnerRouteKey, networkRef, q)
}

// RefreshForwardNetworkMetricsUser refreshes metrics snapshot for a Forward network.
//
//encore:api auth method=POST path=/api/fwd/:networkRef/metrics/refresh
func (s *Service) RefreshForwardNetworkMetricsUser(ctx context.Context, networkRef string) (*ForwardMetricsSummaryResponse, error) {
	return s.RefreshUserForwardNetworkMetrics(ctx, personalOwnerRouteKey, networkRef)
}
