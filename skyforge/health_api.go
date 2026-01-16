package skyforge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type APIHealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
	DB     string `json:"db,omitempty"`
	Redis  string `json:"redis,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GetAPIHealth returns a summary of database and redis health.
//
//encore:api public method=GET path=/api/health
func (s *Service) GetAPIHealth(ctx context.Context) (*APIHealthResponse, error) {
	if s.db != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		if err := s.db.PingContext(pingCtx); err != nil {
			return nil, errs.B().
				Code(errs.Unavailable).
				Msg("database unavailable").
				Meta("db", "down").
				Meta("error", sanitizeError(err)).
				Err()
		}
	}
	return &APIHealthResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type LDAPHealthResponse struct {
	Status   string `json:"status"`
	URL      string `json:"url"`
	StartTLS bool   `json:"starttls"`
	Time     string `json:"time"`
}

// GetLDAPHealth checks LDAP connectivity.
//
//encore:api public method=GET path=/api/health/ldap
func (s *Service) GetLDAPHealth(ctx context.Context) (*LDAPHealthResponse, error) {
	if strings.TrimSpace(s.cfg.LDAP.URL) == "" || strings.TrimSpace(s.cfg.LDAP.BindTemplate) == "" {
		return &LDAPHealthResponse{
			Status:   "disabled",
			URL:      "",
			StartTLS: false,
			Time:     time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := checkLDAPConnectivity(checkCtx, s.cfg.LDAP); err != nil {
		return nil, errs.B().
			Code(errs.Unavailable).
			Msg("ldap unavailable").
			Meta("error", sanitizeError(err)).
			Err()
	}
	return &LDAPHealthResponse{
		Status:   "ok",
		URL:      s.cfg.LDAP.URL,
		StartTLS: s.cfg.LDAP.UseStartTLS,
		Time:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type EveHealthParams struct {
	EveServer string `query:"eve_server"`
	Full      string `query:"full"`
}

type EveHealthServerResult struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Transport string `json:"transport,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Error     string `json:"error,omitempty"`
}

type EveHealthResponse struct {
	Status   string                  `json:"status"`
	OK       int                     `json:"ok"`
	Total    int                     `json:"total"`
	Servers  []EveHealthServerResult `json:"servers"`
	Selected string                  `json:"selected,omitempty"`
	Full     bool                    `json:"full"`
	Time     string                  `json:"time"`
}

// GetEveHealth checks configured EVE-NG endpoints.
//
//encore:api public method=GET path=/api/health/eve
func (s *Service) GetEveHealth(ctx context.Context, params *EveHealthParams) (*EveHealthResponse, error) {
	// Deprecated: Skyforge is moving to a pure BYO-server model (workspace-scoped servers only).
	// Use `/api/workspaces/:id/eve/servers/:serverID/health` instead.
	return &EveHealthResponse{
		Status:  "disabled",
		OK:      0,
		Total:   0,
		Servers: []EveHealthServerResult{},
		Full:    false,
		Time:    time.Now().UTC().Format(time.RFC3339),
	}, nil

	selectedName := ""
	full := false
	if params != nil {
		selectedName = strings.TrimSpace(params.EveServer)
		if raw := strings.TrimSpace(strings.ToLower(params.Full)); raw == "1" || raw == "true" {
			full = true
		}
	}

	servers := s.cfg.EveServers
	if len(servers) == 0 && s.cfg.Labs.EveAPIURL != "" {
		servers = []EveServerConfig{{
			Name:          "eve-default",
			APIURL:        s.cfg.Labs.EveAPIURL,
			Username:      s.cfg.Labs.EveUsername,
			Password:      s.cfg.Labs.EvePassword,
			SkipTLSVerify: s.cfg.Labs.EveSkipTLSVerify,
		}}
	}

	filtered := make([]EveServerConfig, 0, len(servers))
	for _, server := range servers {
		if selectedName == "" || strings.EqualFold(strings.TrimSpace(server.Name), selectedName) {
			filtered = append(filtered, server)
		}
	}
	if selectedName != "" && len(filtered) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown eve_server").Err()
	}

	checkCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	tryOne := func(parent context.Context, server EveServerConfig, timeout time.Duration) EveHealthServerResult {
		server = normalizeEveServer(server, s.cfg.Labs)

		name := strings.TrimSpace(server.Name)
		baseRaw := strings.TrimRight(strings.TrimSpace(server.APIURL), "/")
		webRaw := strings.TrimRight(strings.TrimSpace(server.WebURL), "/")
		sshHost := strings.TrimSpace(server.SSHHost)
		sshUser := strings.TrimSpace(server.SSHUser)

		if name == "" {
			return EveHealthServerResult{Name: name, Status: "error", Error: "invalid config"}
		}

		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()

		sshErr := error(nil)
		if strings.TrimSpace(s.cfg.Labs.EveSSHKeyFile) != "" && sshHost != "" {
			sshCfg := NetlabConfig{
				SSHHost:    sshHost,
				SSHUser:    sshUser,
				SSHKeyFile: strings.TrimSpace(s.cfg.Labs.EveSSHKeyFile),
				StateRoot:  "/",
			}
			client, err := dialSSH(sshCfg)
			if err != nil {
				sshErr = err
			} else {
				defer client.Close()

				labsPath := strings.TrimSpace(server.LabsPath)
				if labsPath == "" {
					labsPath = strings.TrimSpace(s.cfg.Labs.EveLabsPath)
				}
				cmd := fmt.Sprintf("test -d %q && test -r %q", labsPath, labsPath)
				if _, err := runSSHCommand(client, cmd, timeout); err != nil {
					sshErr = err
				} else {
					endpoint := "ssh:" + sshHost
					if webRaw != "" {
						endpoint = webRaw
					} else if baseRaw != "" {
						endpoint = baseRaw
					}
					return EveHealthServerResult{Name: name, Status: "ok", Transport: "ssh", Endpoint: endpoint}
				}
			}
		}

		if baseRaw == "" {
			if sshErr != nil {
				return EveHealthServerResult{Name: name, Status: "error", Transport: "ssh", Endpoint: "ssh:" + sshHost, Error: sanitizeError(sshErr)}
			}
			return EveHealthServerResult{Name: name, Status: "error", Error: "missing apiUrl/webUrl (or configure SSH)"}
		}
		if strings.TrimSpace(server.Username) == "" || strings.TrimSpace(server.Password) == "" {
			if sshErr != nil {
				return EveHealthServerResult{Name: name, Status: "error", Transport: "ssh", Endpoint: "ssh:" + sshHost, Error: sanitizeError(sshErr)}
			}
			return EveHealthServerResult{Name: name, Status: "error", Transport: "eve-native", Endpoint: baseRaw, Error: "missing credentials (or configure SSH)"}
		}

		jar, _ := cookiejar.New(nil)
		transport := &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: server.SkipTLSVerify},
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		client := &http.Client{
			Timeout:   timeout,
			Jar:       jar,
			Transport: transport,
		}

		var lastErr error
		var lastEndpoint string
		for _, base := range candidateEveBaseURLs(baseRaw) {
			base = strings.TrimRight(strings.TrimSpace(base), "/")
			if base == "" {
				continue
			}
			if base == lastEndpoint {
				continue
			}
			lastEndpoint = base

			if err := eveLogin(ctx, client, base, server.Username, server.Password); err != nil {
				lastErr = err
				continue
			}
			if _, endpoint, err := eveGetFolderListing(ctx, client, base, ""); err != nil {
				lastErr = err
				lastEndpoint = endpoint
				continue
			}

			return EveHealthServerResult{Name: name, Status: "ok", Transport: "eve-native", Endpoint: base}
		}

		if lastErr == nil {
			lastErr = fmt.Errorf("unable to reach eve-ng")
		}
		if sshErr != nil {
			return EveHealthServerResult{
				Name:      name,
				Status:    "error",
				Transport: "ssh",
				Endpoint:  "ssh:" + sshHost,
				Error:     sanitizeError(fmt.Errorf("eve-ng ssh failed (%v); native api failed (%v)", sshErr, lastErr)),
			}
		}
		return EveHealthServerResult{Name: name, Status: "error", Transport: "eve-native", Endpoint: lastEndpoint, Error: sanitizeError(lastErr)}
	}

	results := make([]EveHealthServerResult, 0, len(filtered))
	okCount := 0

	if !full && selectedName == "" {
		for _, server := range filtered {
			res := tryOne(checkCtx, server, 4*time.Second)
			results = append(results, res)
			if res.Status == "ok" {
				okCount = 1
				break
			}
		}
	} else {
		type indexed struct {
			i int
			r EveHealthServerResult
		}
		ch := make(chan indexed, len(filtered))
		for i, server := range filtered {
			go func(i int, server EveServerConfig) {
				ch <- indexed{i: i, r: tryOne(checkCtx, server, 4*time.Second)}
			}(i, server)
		}
		out := make([]EveHealthServerResult, len(filtered))
		for range filtered {
			res := <-ch
			out[res.i] = res.r
			if res.r.Status == "ok" {
				okCount++
			}
		}
		results = append(results, out...)
	}

	response := &EveHealthResponse{
		Status:   "error",
		OK:       okCount,
		Total:    len(results),
		Servers:  results,
		Selected: selectedName,
		Full:     full,
		Time:     time.Now().UTC().Format(time.RFC3339),
	}
	if okCount > 0 {
		response.Status = "ok"
		return response, nil
	}
	return nil, errs.B().
		Code(errs.Unavailable).
		Msg("eve-ng unavailable").
		Meta("servers", results).
		Meta("selected", selectedName).
		Err()
}
