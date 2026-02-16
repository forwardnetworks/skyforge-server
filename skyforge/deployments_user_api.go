package skyforge

import "context"

const personalOwnerRouteKey = "me"

// ListDeployments returns per-user deployments without container path parameters.
//
//encore:api auth method=GET path=/api/deployments
func (s *Service) ListDeployments(ctx context.Context) (*UserDeploymentListResponse, error) {
	return s.ListUserDeployments(ctx, personalOwnerRouteKey)
}

// CreateDeployment creates a deployment in the authenticated user's personal context.
//
//encore:api auth method=POST path=/api/deployments
func (s *Service) CreateDeployment(ctx context.Context, req *UserDeploymentCreateRequest) (*UserDeployment, error) {
	return s.CreateUserDeployment(ctx, personalOwnerRouteKey, req)
}

// UpdateDeployment updates a deployment in the authenticated user's personal context.
//
//encore:api auth method=PUT path=/api/deployments/:deploymentID
func (s *Service) UpdateDeployment(ctx context.Context, deploymentID string, req *UserDeploymentUpdateRequest) (*UserDeployment, error) {
	return s.UpdateUserDeployment(ctx, personalOwnerRouteKey, deploymentID, req)
}

// DeleteDeployment deletes a deployment in the authenticated user's personal context.
//
//encore:api auth method=DELETE path=/api/deployments/:deploymentID
func (s *Service) DeleteDeployment(ctx context.Context, deploymentID string, req *UserDeploymentDeleteRequest) (*UserDeploymentActionResponse, error) {
	return s.DeleteUserDeployment(ctx, personalOwnerRouteKey, deploymentID, req)
}

// RunDeploymentAction runs a deployment action in the authenticated user's personal context.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/action
func (s *Service) RunDeploymentAction(ctx context.Context, deploymentID string, req *UserDeploymentOpRequest) (*UserDeploymentActionResponse, error) {
	return s.RunUserDeploymentAction(ctx, personalOwnerRouteKey, deploymentID, req)
}

// GetDeploymentInfo returns deployment runtime details for the authenticated user.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/info
func (s *Service) GetDeploymentInfo(ctx context.Context, deploymentID string) (*UserDeploymentInfoResponse, error) {
	return s.GetUserDeploymentInfo(ctx, personalOwnerRouteKey, deploymentID)
}

// NetlabConnectForDeployment proxies netlab connect for a deployment.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/netlab/connect
func (s *Service) NetlabConnectForDeployment(ctx context.Context, deploymentID string, req *NetlabConnectRequest) (*NetlabConnectResponse, error) {
	return s.NetlabConnect(ctx, personalOwnerRouteKey, deploymentID, req)
}

// GetDeploymentNetlabGraph returns a rendered netlab graph for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/netlab-graph
func (s *Service) GetDeploymentNetlabGraph(ctx context.Context, deploymentID string) (*NetlabGraphResponse, error) {
	return s.GetUserDeploymentNetlabGraph(ctx, personalOwnerRouteKey, deploymentID)
}

// StartDeployment starts a deployment in the authenticated user's personal context.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/start
func (s *Service) StartDeployment(ctx context.Context, deploymentID string, req *UserDeploymentStartRequest) (*UserDeploymentActionResponse, error) {
	return s.StartUserDeployment(ctx, personalOwnerRouteKey, deploymentID, req)
}

// StopDeployment stops a deployment in the authenticated user's personal context.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/stop
func (s *Service) StopDeployment(ctx context.Context, deploymentID string) (*UserDeploymentActionResponse, error) {
	return s.StopUserDeployment(ctx, personalOwnerRouteKey, deploymentID)
}

// DestroyDeployment destroys a deployment in the authenticated user's personal context.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/destroy
func (s *Service) DestroyDeployment(ctx context.Context, deploymentID string) (*UserDeploymentActionResponse, error) {
	return s.DestroyUserDeployment(ctx, personalOwnerRouteKey, deploymentID)
}

// GetDeploymentTopology returns topology graph data for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/topology
func (s *Service) GetDeploymentTopology(ctx context.Context, deploymentID string) (*DeploymentTopologyResponse, error) {
	return s.GetUserDeploymentTopology(ctx, personalOwnerRouteKey, deploymentID)
}

// GetDeploymentInventory returns inventory data for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/inventory
func (s *Service) GetDeploymentInventory(ctx context.Context, deploymentID string, params *DeploymentInventoryParams) (*DeploymentInventoryResponse, error) {
	return s.GetUserDeploymentInventory(ctx, personalOwnerRouteKey, deploymentID, params)
}

// UpdateDeploymentForwardConfig stores deployment Forward settings.
//
//encore:api auth method=PUT path=/api/deployments/:deploymentID/forward
func (s *Service) UpdateDeploymentForwardConfig(ctx context.Context, deploymentID string, req *DeploymentForwardConfigRequest) (*DeploymentForwardConfigResponse, error) {
	return s.UpdateUserDeploymentForwardConfig(ctx, personalOwnerRouteKey, deploymentID, req)
}

// SyncDeploymentForward synchronizes deployment devices to Forward.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/forward/sync
func (s *Service) SyncDeploymentForward(ctx context.Context, deploymentID string) (*DeploymentForwardSyncResponse, error) {
	return s.SyncUserDeploymentForward(ctx, personalOwnerRouteKey, deploymentID)
}

// GetDeploymentCapacitySummary returns capacity summary for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/capacity/summary
func (s *Service) GetDeploymentCapacitySummary(ctx context.Context, deploymentID string) (*DeploymentCapacitySummaryResponse, error) {
	return s.GetUserDeploymentCapacitySummary(ctx, personalOwnerRouteKey, deploymentID)
}

// RefreshDeploymentCapacityRollups refreshes capacity rollups for a deployment.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/capacity/rollups/refresh
func (s *Service) RefreshDeploymentCapacityRollups(ctx context.Context, deploymentID string, req *capacityRollupRefreshRequest) (*DeploymentCapacityRefreshResponse, error) {
	return s.RefreshUserDeploymentCapacityRollups(ctx, personalOwnerRouteKey, deploymentID, req)
}

// GetDeploymentCapacityInventory returns capacity inventory for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/capacity/inventory
func (s *Service) GetDeploymentCapacityInventory(ctx context.Context, deploymentID string) (*DeploymentCapacityInventoryResponse, error) {
	return s.GetUserDeploymentCapacityInventory(ctx, personalOwnerRouteKey, deploymentID)
}

// GetDeploymentCapacityGrowth returns capacity growth data for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/capacity/growth
func (s *Service) GetDeploymentCapacityGrowth(ctx context.Context, deploymentID string, q *DeploymentCapacityGrowthQuery) (*DeploymentCapacityGrowthResponse, error) {
	return s.GetUserDeploymentCapacityGrowth(ctx, personalOwnerRouteKey, deploymentID, q)
}

// PostDeploymentCapacityInterfaceMetricsHistory returns interface metrics history for selected interfaces.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/capacity/perf/interface-metrics-history
func (s *Service) PostDeploymentCapacityInterfaceMetricsHistory(ctx context.Context, deploymentID string, req *capacityInterfaceMetricsHistoryRequest) (*CapacityPerfProxyResponse, error) {
	return s.PostUserDeploymentCapacityInterfaceMetricsHistory(ctx, personalOwnerRouteKey, deploymentID, req)
}

// PostDeploymentCapacityDeviceMetricsHistory returns device metrics history for selected devices.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/capacity/perf/device-metrics-history
func (s *Service) PostDeploymentCapacityDeviceMetricsHistory(ctx context.Context, deploymentID string, req *capacityDeviceSet) (*CapacityPerfProxyResponse, error) {
	return s.PostUserDeploymentCapacityDeviceMetricsHistory(ctx, personalOwnerRouteKey, deploymentID, req)
}

// GetDeploymentCapacityUnhealthyDevices returns unhealthy devices from capacity perf data.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/capacity/perf/unhealthy-devices
func (s *Service) GetDeploymentCapacityUnhealthyDevices(ctx context.Context, deploymentID string, q *CapacityUnhealthyDevicesQuery) (*CapacityPerfProxyResponse, error) {
	return s.GetUserDeploymentCapacityUnhealthyDevices(ctx, personalOwnerRouteKey, deploymentID, q)
}

// GetDeploymentCapacityUnhealthyInterfaces returns unhealthy interfaces from capacity perf data.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/capacity/perf/unhealthy-interfaces
func (s *Service) GetDeploymentCapacityUnhealthyInterfaces(ctx context.Context, deploymentID string, req *CapacityUnhealthyInterfacesRequest) (*CapacityPerfProxyResponse, error) {
	return s.GetUserDeploymentCapacityUnhealthyInterfaces(ctx, personalOwnerRouteKey, deploymentID, req)
}

// SetDeploymentLinkImpairment applies impairment controls to a deployment link.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/links/impair
func (s *Service) SetDeploymentLinkImpairment(ctx context.Context, deploymentID string, req *LinkImpairmentRequest) (*LinkImpairmentResponse, error) {
	return s.SetUserDeploymentLinkImpairment(ctx, personalOwnerRouteKey, deploymentID, req)
}

// UpdateDeploymentLinkAdmin toggles link admin-state up/down.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/links/admin
func (s *Service) UpdateDeploymentLinkAdmin(ctx context.Context, deploymentID string, req *DeploymentLinkAdminRequest) (*DeploymentLinkAdminResponse, error) {
	return s.UpdateUserDeploymentLinkAdmin(ctx, personalOwnerRouteKey, deploymentID, req)
}

// CaptureDeploymentLinkPcap captures packets on one side of a deployment link.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/links/capture
func (s *Service) CaptureDeploymentLinkPcap(ctx context.Context, deploymentID string, req *DeploymentLinkCaptureRequest) (*DeploymentLinkCaptureResponse, error) {
	return s.CaptureUserDeploymentLinkPcap(ctx, personalOwnerRouteKey, deploymentID, req)
}

// GetDeploymentLinkStats returns current link counters for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/links/stats
func (s *Service) GetDeploymentLinkStats(ctx context.Context, deploymentID string) (*LinkStatsSnapshot, error) {
	return s.GetUserDeploymentLinkStats(ctx, personalOwnerRouteKey, deploymentID)
}

// ListDeploymentUIEvents lists persisted UI events for a deployment.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/ui-events
func (s *Service) ListDeploymentUIEvents(ctx context.Context, deploymentID string, params *ListDeploymentUIEventsParams) (*ListDeploymentUIEventsResponse, error) {
	return s.ListUserDeploymentUIEvents(ctx, personalOwnerRouteKey, deploymentID, params)
}

// GetDeploymentNodeLogs returns node logs.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/nodes/:node/logs
func (s *Service) GetDeploymentNodeLogs(ctx context.Context, deploymentID, node string, q *UserDeploymentNodeLogsParams) (*UserDeploymentNodeLogsResponse, error) {
	return s.GetUserDeploymentNodeLogs(ctx, personalOwnerRouteKey, deploymentID, node, q)
}

// GetDeploymentNodeDescribe returns node pod status.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/nodes/:node/describe
func (s *Service) GetDeploymentNodeDescribe(ctx context.Context, deploymentID, node string) (*UserDeploymentNodeDescribeResponse, error) {
	return s.GetUserDeploymentNodeDescribe(ctx, personalOwnerRouteKey, deploymentID, node)
}

// GetDeploymentNodeInterfaces returns node interfaces and counters.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/nodes/:node/interfaces
func (s *Service) GetDeploymentNodeInterfaces(ctx context.Context, deploymentID, node string) (*DeploymentNodeInterfacesResponse, error) {
	return s.GetUserDeploymentNodeInterfaces(ctx, personalOwnerRouteKey, deploymentID, node)
}

// GetDeploymentNodeRunningConfig returns running config for a NOS node.
//
//encore:api auth method=GET path=/api/deployments/:deploymentID/nodes/:node/running-config
func (s *Service) GetDeploymentNodeRunningConfig(ctx context.Context, deploymentID, node string) (*DeploymentNodeRunningConfigResponse, error) {
	return s.GetUserDeploymentNodeRunningConfig(ctx, personalOwnerRouteKey, deploymentID, node)
}

// SaveDeploymentNodeConfig persists a node startup config when supported.
//
//encore:api auth method=POST path=/api/deployments/:deploymentID/nodes/:node/save-config
func (s *Service) SaveDeploymentNodeConfig(ctx context.Context, deploymentID, node string) (*UserDeploymentNodeSaveConfigResponse, error) {
	return s.SaveUserDeploymentNodeConfig(ctx, personalOwnerRouteKey, deploymentID, node)
}

// CreateContainerlabDeploymentFromYAMLUser creates containerlab deployment from YAML.
//
//encore:api auth method=POST path=/api/deployments-designer/containerlab/from-yaml
func (s *Service) CreateContainerlabDeploymentFromYAMLUser(ctx context.Context, req *CreateContainerlabDeploymentFromYAMLRequest) (*CreateContainerlabDeploymentFromYAMLResponse, error) {
	return s.CreateContainerlabDeploymentFromYAML(ctx, personalOwnerRouteKey, req)
}

// CreateClabernetesDeploymentFromYAMLUser creates clabernetes deployment from YAML.
//
//encore:api auth method=POST path=/api/deployments-designer/clabernetes/from-yaml
func (s *Service) CreateClabernetesDeploymentFromYAMLUser(ctx context.Context, req *CreateClabernetesDeploymentFromYAMLRequest) (*CreateClabernetesDeploymentFromYAMLResponse, error) {
	return s.CreateClabernetesDeploymentFromYAML(ctx, personalOwnerRouteKey, req)
}

// SaveContainerlabTopologyYAMLUser stores containerlab topology YAML in the user repo.
//
//encore:api auth method=POST path=/api/containerlab/topologies
func (s *Service) SaveContainerlabTopologyYAMLUser(ctx context.Context, req *SaveContainerlabTopologyYAMLRequest) (*SaveContainerlabTopologyYAMLResponse, error) {
	return s.SaveContainerlabTopologyYAML(ctx, personalOwnerRouteKey, req)
}

// SaveNetlabTopologyYAMLUser stores netlab topology YAML in the user repo.
//
//encore:api auth method=POST path=/api/netlab/topologies
func (s *Service) SaveNetlabTopologyYAMLUser(ctx context.Context, req *SaveNetlabTopologyYAMLRequest) (*SaveNetlabTopologyYAMLResponse, error) {
	return s.SaveNetlabTopologyYAML(ctx, personalOwnerRouteKey, req)
}

// CreateClabernetesDeploymentFromTemplateUser creates clabernetes deployment from template.
//
//encore:api auth method=POST path=/api/deployments-designer/clabernetes/from-template
func (s *Service) CreateClabernetesDeploymentFromTemplateUser(ctx context.Context, req *CreateDeploymentFromTemplateRequest) (*CreateDeploymentFromTemplateResponse, error) {
	return s.CreateClabernetesDeploymentFromTemplate(ctx, personalOwnerRouteKey, req)
}

// CreateContainerlabDeploymentFromTemplateUser creates containerlab deployment from template.
//
//encore:api auth method=POST path=/api/deployments-designer/containerlab/from-template
func (s *Service) CreateContainerlabDeploymentFromTemplateUser(ctx context.Context, req *CreateContainerlabDeploymentFromTemplateRequest) (*CreateDeploymentFromTemplateResponse, error) {
	return s.CreateContainerlabDeploymentFromTemplate(ctx, personalOwnerRouteKey, req)
}
