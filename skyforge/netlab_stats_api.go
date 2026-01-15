package skyforge

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
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
	if s == nil {
		return &NetlabStatsResponse{Servers: nil}, nil
	}
	servers := s.cfg.NetlabServers
	if len(servers) == 0 {
		return &NetlabStatsResponse{Servers: nil}, nil
	}
	out := make([]NetlabStatsServer, 0, len(servers))
	for _, server := range servers {
		server = normalizeNetlabServer(server, s.cfg.Netlab)
		name := strings.TrimSpace(server.Name)
		if name == "" {
			name = strings.TrimSpace(server.SSHHost)
		}
		rec := NetlabStatsServer{Name: name}

		apiURL := strings.TrimSpace(server.APIURL)
		if apiURL == "" && strings.TrimSpace(server.SSHHost) != "" {
			apiURL = strings.TrimRight("https://"+strings.TrimSpace(server.SSHHost)+"/netlab", "/")
		}
		if apiURL == "" {
			rec.Status = "unknown"
			rec.Error = "netlab api url is not configured"
			out = append(out, rec)
			continue
		}

		if strings.TrimSpace(server.APIToken) == "" {
			rec.Status = "degraded"
			rec.Error = "netlab api token is not configured"
			out = append(out, rec)
			continue
		}

		ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp, body, err := netlabAPIGet(ctxReq, strings.TrimRight(apiURL, "/")+"/stats", server.APIInsecure, netlabAPIAuth{BearerToken: strings.TrimSpace(server.APIToken)})
		cancel()
		if err != nil {
			rec.Status = "degraded"
			rec.Error = err.Error()
			out = append(out, rec)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			rec.Status = "degraded"
			rec.Error = strings.TrimSpace(string(body))
			out = append(out, rec)
			continue
		}

		var payload netlabStatsPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			log.Printf("netlab stats decode: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode netlab stats").Err()
		}
		rec.Status = "ok"
		rec.CPUPercent = payload.CPUPercent
		rec.MemPercent = payload.MemPercent
		rec.DiskPercent = payload.DiskPercent
		out = append(out, rec)
	}

	return &NetlabStatsResponse{Servers: out}, nil
}
