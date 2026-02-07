package skyforge

type CapacityRollupRow struct {
	ObjectType         string   `json:"objectType"`
	ObjectID           string   `json:"objectId"`
	Metric             string   `json:"metric"`
	Window             string   `json:"window"`
	PeriodEnd          string   `json:"periodEnd"`
	Samples            int      `json:"samples"`
	Avg                *float64 `json:"avg,omitempty"`
	P95                *float64 `json:"p95,omitempty"`
	P99                *float64 `json:"p99,omitempty"`
	Max                *float64 `json:"max,omitempty"`
	SlopePerDay        *float64 `json:"slopePerDay,omitempty"`
	ForecastCrossingTS *string  `json:"forecastCrossingTs,omitempty"`
	Threshold          *float64 `json:"threshold,omitempty"`
	Details            JSONMap  `json:"details,omitempty"`
	CreatedAt          string   `json:"createdAt,omitempty"`
	ForwardNetworkID   string   `json:"forwardNetworkId,omitempty"`
	DeploymentID       string   `json:"deploymentId,omitempty"`
	WorkspaceID        string   `json:"workspaceId,omitempty"`
}

type DeploymentCapacitySummaryResponse struct {
	WorkspaceID  string              `json:"workspaceId"`
	DeploymentID string              `json:"deploymentId"`
	ForwardID    string              `json:"forwardNetworkId"`
	AsOf         string              `json:"asOf,omitempty"`
	Rollups      []CapacityRollupRow `json:"rollups"`
	Stale        bool                `json:"stale"`
}

type DeploymentCapacityRefreshResponse struct {
	WorkspaceID  string  `json:"workspaceId"`
	DeploymentID string  `json:"deploymentId"`
	Run          JSONMap `json:"run"`
}
