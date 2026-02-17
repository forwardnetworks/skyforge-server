package skyforge

import "context"

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/assurance/summary
func (s *Service) GetFwdNetworkAssuranceSummary(ctx context.Context, networkRef string, params *ForwardAssuranceSummaryParams) (*ForwardAssuranceSummaryResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkAssuranceSummary(ctx, id, networkRef, params)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/refresh
func (s *Service) RefreshFwdNetworkAssurance(ctx context.Context, networkRef string) (*ForwardAssuranceSummaryResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.RefreshUserContextForwardNetworkAssurance(ctx, id, networkRef)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/demo/seed
func (s *Service) SeedFwdNetworkAssuranceDemo(ctx context.Context, networkRef string) (*ForwardAssuranceDemoSeedResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.SeedUserContextForwardNetworkAssuranceDemo(ctx, id, networkRef)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/assurance/summary/history
func (s *Service) ListFwdNetworkAssuranceSummaryHistory(ctx context.Context, networkRef string, params *ForwardAssuranceHistoryParams) (*ForwardAssuranceHistoryResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.ListUserContextForwardNetworkAssuranceSummaryHistory(ctx, id, networkRef, params)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/assurance/studio/scenarios
func (s *Service) ListFwdNetworkAssuranceStudioScenarios(ctx context.Context, networkRef string) (*AssuranceStudioListScenariosResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.ListUserContextForwardNetworkAssuranceStudioScenarios(ctx, id, networkRef)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/studio/scenarios
func (s *Service) CreateFwdNetworkAssuranceStudioScenario(ctx context.Context, networkRef string, req *AssuranceStudioCreateScenarioRequest) (*AssuranceStudioScenario, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.CreateUserContextForwardNetworkAssuranceStudioScenario(ctx, id, networkRef, req)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/assurance/studio/scenarios/:scenarioId
func (s *Service) GetFwdNetworkAssuranceStudioScenario(ctx context.Context, networkRef, scenarioId string) (*AssuranceStudioScenario, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkAssuranceStudioScenario(ctx, id, networkRef, scenarioId)
}

//encore:api auth method=PUT path=/api/fwd/networks/:networkRef/assurance/studio/scenarios/:scenarioId
func (s *Service) UpdateFwdNetworkAssuranceStudioScenario(ctx context.Context, networkRef, scenarioId string, req *AssuranceStudioUpdateScenarioRequest) (*AssuranceStudioScenario, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.UpdateUserContextForwardNetworkAssuranceStudioScenario(ctx, id, networkRef, scenarioId, req)
}

//encore:api auth method=DELETE path=/api/fwd/networks/:networkRef/assurance/studio/scenarios/:scenarioId
func (s *Service) DeleteFwdNetworkAssuranceStudioScenario(ctx context.Context, networkRef, scenarioId string) (*PolicyReportDecisionResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.DeleteUserContextForwardNetworkAssuranceStudioScenario(ctx, id, networkRef, scenarioId)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/assurance/studio/runs
func (s *Service) ListFwdNetworkAssuranceStudioRuns(ctx context.Context, networkRef string) (*AssuranceStudioListRunsResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.ListUserContextForwardNetworkAssuranceStudioRuns(ctx, id, networkRef)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/studio/runs
func (s *Service) CreateFwdNetworkAssuranceStudioRun(ctx context.Context, networkRef string, req *AssuranceStudioCreateRunRequest) (*AssuranceStudioRun, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.CreateUserContextForwardNetworkAssuranceStudioRun(ctx, id, networkRef, req)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/assurance/studio/runs/:runId
func (s *Service) GetFwdNetworkAssuranceStudioRun(ctx context.Context, networkRef, runId string) (*AssuranceStudioRunDetail, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkAssuranceStudioRun(ctx, id, networkRef, runId)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/studio/evaluate
func (s *Service) PostFwdNetworkAssuranceStudioEvaluate(ctx context.Context, networkRef string, req *AssuranceStudioEvaluateRequest) (*AssuranceStudioEvaluateResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkAssuranceStudioEvaluate(ctx, id, networkRef, req)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/traffic/seeds
func (s *Service) PostFwdNetworkAssuranceTrafficSeeds(ctx context.Context, networkRef string, req *AssuranceTrafficSeedRequest) (*AssuranceTrafficSeedResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkAssuranceTrafficSeeds(ctx, id, networkRef, req)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/assurance/traffic/evaluate
func (s *Service) PostFwdNetworkAssuranceTrafficEvaluate(ctx context.Context, networkRef string, req *AssuranceTrafficEvaluateRequest) (*AssuranceTrafficEvaluateResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkAssuranceTrafficEvaluate(ctx, id, networkRef, req)
}
