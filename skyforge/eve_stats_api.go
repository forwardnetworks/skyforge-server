package skyforge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	CpuPercent    *float64 `json:"cpuPercent,omitempty"`
	MemPercent    *float64 `json:"memPercent,omitempty"`
	DiskPercent   *float64 `json:"diskPercent,omitempty"`
	VCPU          *int     `json:"vCpu,omitempty"`
	MemTotal      *int64   `json:"memTotal,omitempty"`
	DiskAvailable *float64 `json:"diskAvailable,omitempty"`
	QemuNodes     *int     `json:"qemuNodes,omitempty"`
	DynamipsNodes *int     `json:"dynamipsNodes,omitempty"`
	VpcsNodes     *int     `json:"vpcsNodes,omitempty"`
	DockerNodes   *int     `json:"dockerNodes,omitempty"`
	ClusterNodes  *int     `json:"clusterNodes,omitempty"`
	ClusterOnline *int     `json:"clusterOnline,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type EveStatsResponse struct {
	Servers []EveStatsServer `json:"servers"`
}

// GetEveStats returns basic EVE-NG server stats for the status dashboard.
//
//encore:api public method=GET path=/api/eve/stats
func (s *Service) GetEveStats(ctx context.Context, params *EveStatsParams) (*EveStatsResponse, error) {
	_ = params
	servers := []EveServerConfig{}
	_ = servers
	// Deprecated: Skyforge is moving to a pure BYO-server model (workspace-scoped servers only).
	// Use workspace-scoped server health endpoints instead.
	return &EveStatsResponse{Servers: []EveStatsServer{}}, nil

	results := make([]EveStatsServer, 0, len(servers))
	for _, server := range servers {
		result := EveStatsServer{Name: server.Name}
		apiURL, username, password, skipTLS := resolveEveAPIConfig(s.cfg, server)
		if apiURL == "" {
			sshStatus, sshErr := eveStatsViaSSH(s.cfg, server)
			if sshErr != nil {
				result.Error = sanitizeError(sshErr)
			} else {
				result.Status = sshStatus.Status
				result.Version = sshStatus.Version
				result.CpuPercent = sshStatus.CpuPercent
				result.MemPercent = sshStatus.MemPercent
				result.DiskPercent = sshStatus.DiskPercent
				result.VCPU = sshStatus.VCPU
				result.MemTotal = sshStatus.MemTotal
			}
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
			if v, ok := extractEveFloat(payload, "cpu"); ok {
				result.CpuPercent = &v
			}
			if v, ok := extractEveFloat(payload, "mem"); ok {
				result.MemPercent = &v
			}
			if v, ok := extractEveFloat(payload, "disk"); ok {
				result.DiskPercent = &v
			}
			if v, ok := extractEveInt(payload, "vCPU", "vCpu", "vcpu"); ok {
				result.VCPU = &v
			}
			if v, ok := extractEveInt64(payload, "memtotal", "memTotal"); ok {
				result.MemTotal = &v
			}
			if v, ok := extractEveFloat(payload, "diskavailable", "diskAvailable"); ok {
				result.DiskAvailable = &v
			}
			if v, ok := extractEveInt(payload, "qemu"); ok {
				result.QemuNodes = &v
			}
			if v, ok := extractEveInt(payload, "dynamips"); ok {
				result.DynamipsNodes = &v
			}
			if v, ok := extractEveInt(payload, "vpcs"); ok {
				result.VpcsNodes = &v
			}
			if v, ok := extractEveInt(payload, "docker"); ok {
				result.DockerNodes = &v
			}
			clusterMap := extractEveMap(cluster, "data")
			if total, online := summarizeClusterNodes(clusterMap); total > 0 || online > 0 {
				result.ClusterNodes = &total
				result.ClusterOnline = &online
			}
			lastErr = nil
			break
		}
		if lastErr != nil {
			// If API stats fail (common when per-server passwords differ), fall back to SSH so we still
			// surface basic health signals on the status dashboard.
			if sshStatus, sshErr := eveStatsViaSSH(s.cfg, server); sshErr == nil {
				if result.Status == "" {
					result.Status = sshStatus.Status
				}
				if result.Version == "" {
					result.Version = sshStatus.Version
				}
				if result.CpuPercent == nil {
					result.CpuPercent = sshStatus.CpuPercent
				}
				if result.MemPercent == nil {
					result.MemPercent = sshStatus.MemPercent
				}
				if result.DiskPercent == nil {
					result.DiskPercent = sshStatus.DiskPercent
				}
				if result.VCPU == nil {
					result.VCPU = sshStatus.VCPU
				}
				if result.MemTotal == nil {
					result.MemTotal = sshStatus.MemTotal
				}
			}
			result.Error = sanitizeError(lastErr)
		}
		results = append(results, result)
	}

	return &EveStatsResponse{Servers: results}, nil
}

type eveSSHStats struct {
	Status      string
	Version     string
	CpuPercent  *float64
	MemPercent  *float64
	DiskPercent *float64
	VCPU        *int
	MemTotal    *int64
}

func eveStatsViaSSH(cfg Config, server EveServerConfig) (*eveSSHStats, error) {
	if strings.TrimSpace(cfg.Labs.EveSSHKeyFile) == "" || strings.TrimSpace(server.SSHHost) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("missing eve ssh config").Err()
	}
	sshUser := strings.TrimSpace(server.SSHUser)
	if sshUser == "" {
		sshUser = strings.TrimSpace(cfg.Labs.EveSSHUser)
	}
	if sshUser == "" {
		sshUser = "root"
	}

	sshCfg := NetlabConfig{
		SSHHost:    strings.TrimSpace(server.SSHHost),
		SSHUser:    sshUser,
		SSHKeyFile: strings.TrimSpace(cfg.Labs.EveSSHKeyFile),
		StateRoot:  "/",
	}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	labsPath := strings.TrimSpace(server.LabsPath)
	if labsPath == "" {
		labsPath = strings.TrimSpace(cfg.Labs.EveLabsPath)
	}
	if labsPath != "" {
		cmd := fmt.Sprintf("test -d %q && test -r %q", labsPath, labsPath)
		if _, err := runSSHCommand(client, cmd, 6*time.Second); err != nil {
			return nil, err
		}
	}

	out := &eveSSHStats{Status: "ok"}
	if raw, err := runSSHCommand(client, "uname -r 2>/dev/null | head -n1", 6*time.Second); err == nil {
		out.Version = strings.TrimSpace(raw)
	}
	if raw, err := runSSHCommand(client, "nproc 2>/dev/null | head -n1", 6*time.Second); err == nil {
		if v, _ := strconv.Atoi(strings.TrimSpace(raw)); v > 0 {
			out.VCPU = &v
		}
	}
	if raw, err := runSSHCommand(client, "free -m 2>/dev/null | awk '/^Mem:/ {print $2\" \"$3}'", 6*time.Second); err == nil {
		fields := strings.Fields(raw)
		if len(fields) >= 2 {
			total, _ := strconv.ParseFloat(fields[0], 64)
			used, _ := strconv.ParseFloat(fields[1], 64)
			if total > 0 {
				memTotal := int64(total)
				memPercent := (used / total) * 100
				out.MemTotal = &memTotal
				out.MemPercent = &memPercent
			}
		}
	}
	if raw, err := runSSHCommand(client, "df -P / 2>/dev/null | awk 'NR==2 {gsub(/%/,\"\",$5); print $5}'", 6*time.Second); err == nil {
		if v, _ := strconv.ParseFloat(strings.TrimSpace(raw), 64); v >= 0 {
			out.DiskPercent = &v
		}
	}
	if raw, err := runSSHCommand(client, "top -bn1 2>/dev/null | awk -F',' '/Cpu\\(s\\)/ {for(i=1;i<=NF;i++){if($i~/%id/){gsub(/[^0-9.]/,\"\",$i); print 100-$i; exit}}}'", 6*time.Second); err == nil {
		if v, _ := strconv.ParseFloat(strings.TrimSpace(raw), 64); v >= 0 {
			out.CpuPercent = &v
		}
	}
	return out, nil
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
	if apiURL == "" {
		sshHost := strings.TrimSpace(server.SSHHost)
		if sshHost != "" {
			apiURL = "https://" + sshHost
		}
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

func extractEveInt(payload map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case int:
				return v, true
			case int64:
				return int(v), true
			case float64:
				return int(v), true
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					return parsed, true
				}
			}
		}
	}
	return 0, false
}

func extractEveInt64(payload map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case int:
				return int64(v), true
			case int64:
				return v, true
			case float64:
				return int64(v), true
			case string:
				if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
					return parsed, true
				}
			}
		}
	}
	return 0, false
}

func extractEveFloat(payload map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case float64:
				return v, true
			case int:
				return float64(v), true
			case int64:
				return float64(v), true
			case string:
				if parsed, err := strconv.ParseFloat(v, 64); err == nil {
					return parsed, true
				}
			}
		}
	}
	return 0, false
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
		if v, ok := extractEveInt(node, "online"); ok && v == 1 {
			online++
		}
	}
	return total, online
}
