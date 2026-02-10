package skyforge

import "time"

type PolicyReportZone struct {
	ID               string    `json:"id"`
	WorkspaceID      string    `json:"workspaceId"`
	ForwardNetworkID string    `json:"forwardNetworkId"`
	Name             string    `json:"name"`
	Description      string    `json:"description,omitempty"`
	Subnets          []string  `json:"subnets"`
	CreatedBy        string    `json:"createdBy"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type PolicyReportCreateZoneRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Subnets     []string `json:"subnets"`
}

type PolicyReportUpdateZoneRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Subnets     []string `json:"subnets"`
}

type PolicyReportListZonesResponse struct {
	Zones []PolicyReportZone `json:"zones"`
}
