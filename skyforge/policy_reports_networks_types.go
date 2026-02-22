package skyforge

import "time"

type PolicyReportForwardNetwork struct {
	ID                string    `json:"id"`
	UserScopeID       string    `json:"userId"`
	ForwardNetwork    string    `json:"forwardNetworkId"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	CollectorConfigID string    `json:"collectorConfigId,omitempty"`
	CreatedBy         string    `json:"createdBy"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type PolicyReportCreateForwardNetworkRequest struct {
	ForwardNetwork    string `json:"forwardNetworkId"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	CollectorConfigID string `json:"collectorConfigId,omitempty"`
}

type PolicyReportListForwardNetworksResponse struct {
	Networks []PolicyReportForwardNetwork `json:"networks"`
}
