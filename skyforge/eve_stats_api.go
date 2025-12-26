package skyforge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type EveStatsParams struct {
	EveServer string `query:"eve_server" encore:"optional"`
}

type EveStatsServer struct {
	Name          string  `json:"name"`
	Status        string  `json:"status,omitempty"`
	Version       string  `json:"version,omitempty"`
	CpuPercent    float64 `json:"cpuPercent,omitempty"`
	MemPercent    float64 `json:"memPercent,omitempty"`
	DiskPercent   float64 `json:"diskPercent,omitempty"`
	VCPU          int     `json:"vCpu,omitempty"`
	MemTotal      int64   `json:"memTotal,omitempty"`
	DiskAvailable float64 `json:"diskAvailable,omitempty"`
	QemuNodes     int     `json:"qemuNodes,omitempty"`
	DynamipsNodes int     `json:"dynamipsNodes,omitempty"`
	VpcsNodes     int     `json:"vpcsNodes,omitempty"`
	DockerNodes   int     `json:"dockerNodes,omitempty"`
	ClusterNodes  int     `json:"clusterNodes,omitempty"`
	ClusterOnline int     `json:"clusterOnline,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type EveStatsResponse struct {
	Servers []EveStatsServer `json:"servers"`
}

// GetEveStats returns basic EVE-NG server stats for the status dashboard.
//
//encore:api public method=GET path=/api/eve/stats
func (s *Service) GetEveStats(ctx context.Context, params *EveStatsParams) (*EveStatsResponse, error) {
	servers := selectEveServersForStats(s.cfg, strings.TrimSpace(params.EveServer))
	if len(servers) == 0 {
		return &EveStatsResponse{Servers: []EveStatsServer{}}, nil
	}

	results := make([]EveStatsServer, 0, len(servers))
	for _, server := range servers {
		result := EveStatsServer{Name: server.Name}
		apiURL, username, password, skipTLS := resolveEveAPIConfig(s.cfg, server)
		if apiURL == "" {
			result.Error = "missing eve api url"
			results = append(results, result)
			continue
		}
		if username == "" || password == "" {
			result.Error = "missing eve credentials"
			results = append(results, result)
			continue
		}

		jar, _ := cookiejar.New(nil)
		client := &http.Client{
			Timeout: 8 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
			},
		}

		var lastErr error
		for _, base := range candidateEveBaseURLs(apiURL) {
			if err := eveLogin(ctx, client, base, username, password); err != nil {
				lastErr = err
				continue
			}
			status := map[string]any{}
			if err := eveGetJSON(ctx, client, eveEndpoint(base, "/status"), &status); err != nil {
				lastErr = err
				continue
			}
			cluster := map[string]any{}
			_ = eveGetJSON(ctx, client, eveEndpoint(base, "/cluster"), &cluster)
			result.Status = extractEveString(status, "status", "state")
			payload := extractEveMap(status, "data")
			result.Version = extractEveString(payload, "version")
			result.CpuPercent = extractEveFloat(payload, "cpu")
			result.MemPercent = extractEveFloat(payload, "mem")
			result.DiskPercent = extractEveFloat(payload, "disk")
			result.VCPU = extractEveInt(payload, "vCPU", "vcpu")
			result.MemTotal = extractEveInt64(payload, "memtotal", "memTotal")
			result.DiskAvailable = extractEveFloat(payload, "diskavailable", "diskAvailable")
			result.QemuNodes = extractEveInt(payload, "qemu")
			result.DynamipsNodes = extractEveInt(payload, "dynamips")
			result.VpcsNodes = extractEveInt(payload, "vpcs")
			result.DockerNodes = extractEveInt(payload, "docker")
			clusterMap := extractEveMap(cluster, "data")
			result.ClusterNodes, result.ClusterOnline = summarizeClusterNodes(clusterMap)
			lastErr = nil
			break
		}
		if lastErr != nil {
			result.Error = sanitizeError(lastErr)
		}
		results = append(results, result)
	}

	return &EveStatsResponse{Servers: results}, nil
}

func selectEveServersForStats(cfg Config, name string) []EveServerConfig {
	if name != "" {
		if server := eveServerByName(cfg.EveServers, name); server != nil {
			return []EveServerConfig{*server}
		}
		return nil
	}
	if len(cfg.EveServers) > 0 {
		return cfg.EveServers
	}
	if strings.TrimSpace(cfg.Labs.EveAPIURL) != "" {
		return []EveServerConfig{{
			Name:          "eve-default",
			APIURL:        cfg.Labs.EveAPIURL,
			Username:      cfg.Labs.EveUsername,
			Password:      cfg.Labs.EvePassword,
			SkipTLSVerify: cfg.Labs.EveSkipTLSVerify,
		}}
	}
	return nil
}

func resolveEveAPIConfig(cfg Config, server EveServerConfig) (string, string, string, bool) {
	apiURL := strings.TrimSpace(server.APIURL)
	username := strings.TrimSpace(server.Username)
	password := strings.TrimSpace(server.Password)
	skipTLS := server.SkipTLSVerify

	if apiURL == "" {
		apiURL = strings.TrimSpace(cfg.Labs.EveAPIURL)
	}
	if username == "" {
		username = strings.TrimSpace(cfg.Labs.EveUsername)
	}
	if password == "" {
		password = strings.TrimSpace(cfg.Labs.EvePassword)
	}
	if !skipTLS {
		skipTLS = cfg.Labs.EveSkipTLSVerify
	}
	return apiURL, username, password, skipTLS
}

func eveEndpoint(base, path string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, "/api") {
		return base + path
	}
	return base + "/api" + path
}

func eveGetJSON(ctx context.Context, client *http.Client, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return errs.B().Code(errs.Unavailable).Msg("eve api request failed").Err()
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func extractEveString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			if s, ok := value.(string); ok && s != "" {
				return s
			}
		}
	}
	return "unknown"
}

func extractEveInt(payload map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case int:
				return v
			case int64:
				return int(v)
			case float64:
				return int(v)
			}
		}
	}
	return 0
}

func extractEveInt64(payload map[string]any, keys ...string) int64 {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case int:
				return int64(v)
			case int64:
				return v
			case float64:
				return int64(v)
			case string:
				if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
					return parsed
				}
			}
		}
	}
	return 0
}

func extractEveFloat(payload map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case float64:
				return v
			case int:
				return float64(v)
			case int64:
				return float64(v)
			case string:
				if parsed, err := strconv.ParseFloat(v, 64); err == nil {
					return parsed
				}
			}
		}
	}
	return 0
}

func extractEveMap(payload map[string]any, key string) map[string]any {
	if value, ok := payload[key]; ok {
		if m, ok := value.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

func summarizeClusterNodes(payload map[string]any) (int, int) {
	if len(payload) == 0 {
		return 0, 0
	}
	total := 0
	online := 0
	for _, raw := range payload {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		total++
		if extractEveInt(node, "online") == 1 {
			online++
		}
	}
	return total, online
}
