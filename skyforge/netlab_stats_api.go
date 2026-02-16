package skyforge

import (
	"context"
)

type NetlabStatsParams struct{}

type NetlabStatsServer struct {
	Name        string   `json:"name"`
	Status      string   `json:"status,omitempty"`
	CPUPercent  *float64 `json:"cpuPercent,omitempty"`
	MemPercent  *float64 `json:"memPercent,omitempty"`
	DiskPercent *float64 `json:"diskPercent,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type NetlabStatsResponse struct {
	Servers []NetlabStatsServer `json:"servers"`
}

type netlabStatsPayload struct {
	CPUPercent  *float64 `json:"cpuPercent,omitempty"`
	MemPercent  *float64 `json:"memPercent,omitempty"`
	DiskPercent *float64 `json:"diskPercent,omitempty"`
}

// GetNetlabStats returns basic Netlab server stats for the status dashboard.
//
//encore:api public method=GET path=/api/netlab/stats
func (s *Service) GetNetlabStats(ctx context.Context, _ *NetlabStatsParams) (*NetlabStatsResponse, error) {
	// Deprecated: Skyforge is moving to a pure BYO-server model (scope-scoped servers only).
	// Prefer scope health endpoints and any per-scope dashboards.
	return &NetlabStatsResponse{Servers: []NetlabStatsServer{}}, nil
}
