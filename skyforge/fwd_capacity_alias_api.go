package skyforge

import "context"

func (s *Service) resolveCurrentUserContextID(ctx context.Context) (string, error) {
	user, err := requireAuthUser()
	if err != nil {
		return "", err
	}
	pc, err := s.userContextForCurrentUser(ctx, user)
	if err != nil {
		return "", err
	}
	return pc.userContext.ID, nil
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/summary
func (s *Service) GetFwdNetworkCapacitySummary(ctx context.Context, networkRef string) (*ForwardNetworkCapacitySummaryResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacitySummary(ctx, id, networkRef)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/capacity/rollups/refresh
func (s *Service) RefreshFwdNetworkCapacityRollups(ctx context.Context, networkRef string) (*ForwardNetworkCapacityRefreshResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.RefreshUserContextForwardNetworkCapacityRollups(ctx, id, networkRef)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/inventory
func (s *Service) GetFwdNetworkCapacityInventory(ctx context.Context, networkRef string) (*ForwardNetworkCapacityInventoryResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityInventory(ctx, id, networkRef)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/growth
func (s *Service) GetFwdNetworkCapacityGrowth(ctx context.Context, networkRef string, q *DeploymentCapacityGrowthQuery) (*ForwardNetworkCapacityGrowthResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityGrowth(ctx, id, networkRef, q)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/perf/interface-metrics
func (s *Service) GetFwdNetworkCapacityInterfaceMetrics(ctx context.Context, networkRef string, q *CapacityInterfaceMetricsQuery) (*CapacityPerfProxyResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityInterfaceMetrics(ctx, id, networkRef, q)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/capacity/perf/interface-metrics-history
func (s *Service) PostFwdNetworkCapacityInterfaceMetricsHistory(ctx context.Context, networkRef string, req *capacityInterfaceMetricsHistoryRequest) (*CapacityPerfProxyResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkCapacityInterfaceMetricsHistory(ctx, id, networkRef, req)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/capacity/perf/device-metrics-history
func (s *Service) PostFwdNetworkCapacityDeviceMetricsHistory(ctx context.Context, networkRef string, req *capacityDeviceSet) (*CapacityPerfProxyResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkCapacityDeviceMetricsHistory(ctx, id, networkRef, req)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/perf/unhealthy-devices
func (s *Service) GetFwdNetworkCapacityUnhealthyDevices(ctx context.Context, networkRef string, q *CapacityUnhealthyDevicesQuery) (*CapacityPerfProxyResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityUnhealthyDevices(ctx, id, networkRef, q)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/capacity/perf/unhealthy-interfaces
func (s *Service) PostFwdNetworkCapacityUnhealthyInterfaces(ctx context.Context, networkRef string, req *CapacityUnhealthyInterfacesRequest) (*CapacityPerfProxyResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkCapacityUnhealthyInterfaces(ctx, id, networkRef, req)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/coverage
func (s *Service) GetFwdNetworkCapacityCoverage(ctx context.Context, networkRef string) (*ForwardNetworkCapacityCoverageResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityCoverage(ctx, id, networkRef)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/snapshot-delta
func (s *Service) GetFwdNetworkCapacitySnapshotDelta(ctx context.Context, networkRef string) (*ForwardNetworkCapacitySnapshotDeltaResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacitySnapshotDelta(ctx, id, networkRef)
}

//encore:api auth method=GET path=/api/fwd/networks/:networkRef/capacity/upgrade-candidates
func (s *Service) GetFwdNetworkCapacityUpgradeCandidates(ctx context.Context, networkRef string, q *ForwardNetworkCapacityUpgradeCandidatesQuery) (*ForwardNetworkCapacityUpgradeCandidatesResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityUpgradeCandidates(ctx, id, networkRef, q)
}

//encore:api auth method=POST path=/api/fwd/networks/:networkRef/capacity/path-bottlenecks
func (s *Service) PostFwdNetworkCapacityPathBottlenecks(ctx context.Context, networkRef string, req *ForwardNetworkCapacityPathBottlenecksRequest) (*ForwardNetworkCapacityPathBottlenecksResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.PostUserContextForwardNetworkCapacityPathBottlenecks(ctx, id, networkRef, req)
}

//encore:api auth method=GET path=/api/fwd/capacity/networks/portfolio
func (s *Service) GetFwdNetworkCapacityPortfolio(ctx context.Context) (*ForwardNetworkCapacityPortfolioResponse, error) {
	id, err := s.resolveCurrentUserContextID(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetUserContextForwardNetworkCapacityPortfolio(ctx, id)
}
