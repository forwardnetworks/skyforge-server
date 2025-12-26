package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type LabsRunningParams struct {
	Provider     string `query:"provider" encore:"optional"`
	EveServer    string `query:"eve_server" encore:"optional"`
	NetlabServer string `query:"netlab_server" encore:"optional"`
	ProjectID    string `query:"project_id" encore:"optional"`
}

type LabsRunningResponse struct {
	Sources   []LabSource  `json:"sources"`
	LabsURL   string       `json:"labs_url"`
	Labs      []LabSummary `json:"labs"`
	Timestamp string       `json:"timestamp"`
}

type LabsUserResponse struct {
	Sources   []LabSource  `json:"sources"`
	User      string       `json:"user"`
	LabsURL   string       `json:"labs_url"`
	Labs      []LabSummary `json:"labs"`
	Timestamp string       `json:"timestamp"`
}

type EveServerSummary struct {
	Name          string `json:"name"`
	APIURL        string `json:"apiUrl"`
	WebURL        string `json:"webUrl"`
	SSHHost       string `json:"sshHost"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
}

type EveServersResponse struct {
	Servers []EveServerSummary `json:"servers"`
	User    string             `json:"user"`
}

type NetlabServerSummary struct {
	Name      string `json:"name"`
	SSHHost   string `json:"sshHost"`
	SSHUser   string `json:"sshUser"`
	StateRoot string `json:"stateRoot"`
}

type NetlabServersResponse struct {
	Servers []NetlabServerSummary `json:"servers"`
	User    string                `json:"user"`
}

type NetlabLabsParams struct {
	Limit        string `query:"limit" encore:"optional"`
	ProjectID    string `query:"project_id" encore:"optional"`
	NetlabServer string `query:"netlab_server" encore:"optional"`
}

type NetlabLabsResponse struct {
	User      string    `json:"user"`
	Runner    string    `json:"runner"`
	StateRoot string    `json:"state_root"`
	Labs      []JSONMap `json:"labs"`
}

type NetlabLabParams struct {
	ProjectID    string `query:"project_id" encore:"optional"`
	NetlabServer string `query:"netlab_server" encore:"optional"`
}

type NetlabLabResponse struct {
	User   string  `json:"user"`
	Runner string  `json:"runner"`
	Lab    JSONMap `json:"lab"`
}

// GetLabsRunning returns running labs across providers (public).
//
//encore:api public method=GET path=/api/labs/running
func (s *Service) GetLabsRunning(ctx context.Context, params *LabsRunningParams) (*LabsRunningResponse, error) {
	labsRunningRequests.Add(1)
	provider := ""
	eveServer := ""
	netlabServer := ""
	projectID := ""
	if params != nil {
		provider = strings.TrimSpace(strings.ToLower(params.Provider))
		eveServer = strings.TrimSpace(params.EveServer)
		netlabServer = strings.TrimSpace(params.NetlabServer)
		projectID = strings.TrimSpace(params.ProjectID)
	}
	if projectID != "" && eveServer == "" {
		if pid, err := strconv.Atoi(projectID); err == nil && pid > 0 {
			if projects, err := s.projectStore.load(); err == nil {
				for _, p := range projects {
					if p.SemaphoreProjectID == pid && strings.TrimSpace(p.EveServer) != "" {
						eveServer = strings.TrimSpace(p.EveServer)
						break
					}
				}
			}
		}
	}
	if projectID != "" && netlabServer == "" {
		if pid, err := strconv.Atoi(projectID); err == nil && pid > 0 {
			if projects, err := s.projectStore.load(); err == nil {
				for _, p := range projects {
					if p.SemaphoreProjectID == pid && strings.TrimSpace(p.NetlabServer) != "" {
						netlabServer = strings.TrimSpace(p.NetlabServer)
						break
					}
				}
			}
		}
	}
	labs, sources := listLabProviders(ctx, s.cfg, ProviderQuery{
		Owner:        "",
		Mode:         "running",
		OnlyProvider: provider,
		PublicOnly:   true,
		EveServer:    eveServer,
		NetlabServer: netlabServer,
	})
	return &LabsRunningResponse{
		Sources:   sources,
		LabsURL:   s.cfg.Labs.PublicURL,
		Labs:      labs,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetLabsRunningV1 returns running labs across providers (v1 alias).
//
//encore:api public method=GET path=/api/v1/labs/running
func (s *Service) GetLabsRunningV1(ctx context.Context, params *LabsRunningParams) (*LabsRunningResponse, error) {
	return s.GetLabsRunning(ctx, params)
}

// GetLabsForUser returns labs scoped to the authenticated user.
//
//encore:api auth method=GET path=/api/labs/user
func (s *Service) GetLabsForUser(ctx context.Context, params *LabsRunningParams) (*LabsUserResponse, error) {
	labsUserRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		labsErrors.Add(1)
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	provider := ""
	eveServer := ""
	netlabServer := ""
	projectID := ""
	if params != nil {
		provider = strings.TrimSpace(strings.ToLower(params.Provider))
		eveServer = strings.TrimSpace(params.EveServer)
		netlabServer = strings.TrimSpace(params.NetlabServer)
		projectID = strings.TrimSpace(params.ProjectID)
	}

	ownerOverride := ""
	if projectID != "" {
		if pid, err := strconv.Atoi(projectID); err == nil && pid > 0 {
			if projects, err := s.projectStore.load(); err == nil {
				for _, p := range projects {
					if p.SemaphoreProjectID != pid {
						continue
					}
					if eveServer == "" && strings.TrimSpace(p.EveServer) != "" {
						eveServer = strings.TrimSpace(p.EveServer)
					}
					if netlabServer == "" && strings.TrimSpace(p.NetlabServer) != "" {
						netlabServer = strings.TrimSpace(p.NetlabServer)
					}
					if projectAccessLevelForClaims(s.cfg, p, claims) == "none" {
						labsErrors.Add(1)
						return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
					}
					ownerOverride = projectPrimaryOwner(p)
					break
				}
			}
		}
	}

	owner := user.Username
	if ownerOverride != "" {
		owner = ownerOverride
	}
	labs, sources := listLabProviders(ctx, s.cfg, ProviderQuery{
		Owner:        owner,
		Mode:         "all",
		OnlyProvider: provider,
		PublicOnly:   false,
		EveServer:    eveServer,
		NetlabServer: netlabServer,
	})
	return &LabsUserResponse{
		Sources:   sources,
		User:      owner,
		LabsURL:   s.cfg.Labs.PublicURL,
		Labs:      labs,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetLabsForUserV1 returns labs scoped to the authenticated user (v1 alias).
//
//encore:api auth method=GET path=/api/v1/labs/user
func (s *Service) GetLabsForUserV1(ctx context.Context, params *LabsRunningParams) (*LabsUserResponse, error) {
	return s.GetLabsForUser(ctx, params)
}

// ListEveServers returns configured EVE-NG servers.
//
//encore:api auth method=GET path=/api/eve/servers
func (s *Service) ListEveServers(ctx context.Context) (*EveServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	servers := s.cfg.EveServers
	if len(servers) == 0 && s.cfg.Labs.EveAPIURL != "" {
		servers = []EveServerConfig{{
			Name:          "eve-default",
			APIURL:        s.cfg.Labs.EveAPIURL,
			WebURL:        strings.TrimSuffix(strings.TrimRight(s.cfg.Labs.EveAPIURL, "/"), "/api"),
			SkipTLSVerify: s.cfg.Labs.EveSkipTLSVerify,
			SSHHost: func() string {
				u, _ := url.Parse(s.cfg.Labs.EveAPIURL)
				if u != nil {
					return u.Hostname()
				}
				return ""
			}(),
			SSHUser:  s.cfg.Labs.EveSSHUser,
			LabsPath: s.cfg.Labs.EveLabsPath,
			TmpPath:  s.cfg.Labs.EveTmpPath,
		}}
	}
	out := make([]EveServerSummary, 0, len(servers))
	for _, server := range servers {
		server = normalizeEveServer(server, s.cfg.Labs)
		out = append(out, EveServerSummary{
			Name:          server.Name,
			APIURL:        server.APIURL,
			WebURL:        server.WebURL,
			SSHHost:       server.SSHHost,
			SkipTLSVerify: server.SkipTLSVerify,
		})
	}
	return &EveServersResponse{
		Servers: out,
		User:    user.Username,
	}, nil
}

// ListEveServersV1 returns configured EVE-NG servers (v1 alias).
//
//encore:api auth method=GET path=/api/v1/eve/servers
func (s *Service) ListEveServersV1(ctx context.Context) (*EveServersResponse, error) {
	return s.ListEveServers(ctx)
}

// ListNetlabServers returns configured Netlab runners.
//
//encore:api auth method=GET path=/api/netlab/servers
func (s *Service) ListNetlabServers(ctx context.Context) (*NetlabServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	servers := s.cfg.NetlabServers
	if len(servers) == 0 && len(s.cfg.EveServers) > 0 {
		servers = make([]NetlabServerConfig, 0, len(s.cfg.EveServers))
		for _, eve := range s.cfg.EveServers {
			servers = append(servers, netlabServerFromEve(eve, s.cfg.Netlab, s.cfg.Labs))
		}
	}
	out := make([]NetlabServerSummary, 0, len(servers))
	for _, server := range servers {
		server = normalizeNetlabServer(server, s.cfg.Netlab)
		out = append(out, NetlabServerSummary{
			Name:      server.Name,
			SSHHost:   server.SSHHost,
			SSHUser:   server.SSHUser,
			StateRoot: server.StateRoot,
		})
	}
	return &NetlabServersResponse{
		Servers: out,
		User:    user.Username,
	}, nil
}

// ListNetlabServersV1 returns configured Netlab runners (v1 alias).
//
//encore:api auth method=GET path=/api/v1/netlab/servers
func (s *Service) ListNetlabServersV1(ctx context.Context) (*NetlabServersResponse, error) {
	return s.ListNetlabServers(ctx)
}

// ListNetlabLabs returns Netlab labs metadata.
//
//encore:api auth method=GET path=/api/netlab/labs
func (s *Service) ListNetlabLabs(ctx context.Context, params *NetlabLabsParams) (*NetlabLabsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	limit := 25
	serverName := ""
	projectID := ""
	if params != nil {
		serverName = strings.TrimSpace(params.NetlabServer)
		projectID = strings.TrimSpace(params.ProjectID)
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 100 {
				limit = v
			}
		}
	}
	if projectID != "" {
		if pid, err := strconv.Atoi(projectID); err == nil && pid > 0 {
			if projects, err := s.projectStore.load(); err == nil {
				for _, p := range projects {
					if p.SemaphoreProjectID != pid {
						continue
					}
					if projectAccessLevelForClaims(s.cfg, p, claims) == "none" {
						return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
					}
					if serverName == "" && strings.TrimSpace(p.NetlabServer) != "" {
						serverName = strings.TrimSpace(p.NetlabServer)
					}
					break
				}
			}
		}
	}
	server, resolvedName := resolveNetlabServer(s.cfg, serverName)
	if server == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab runner is not configured").Err()
	}
	netlabCfg := netlabConfigFromServer(*server, s.cfg.Netlab)

	client, err := dialSSH(netlabCfg)
	if err != nil {
		log.Printf("netlab ssh dial: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach netlab runner").Err()
	}
	defer client.Close()

	cmd := fmt.Sprintf("find %q -maxdepth 2 -type f -name metadata.json 2>/dev/null | head -n %d", netlabCfg.StateRoot, limit)
	out, err := runSSHCommand(client, cmd, 10*time.Second)
	if err != nil {
		log.Printf("netlab list cmd: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list labs").Err()
	}
	paths := strings.Fields(out)

	labs := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		content, err := runSSHCommand(client, fmt.Sprintf("cat %q", p), 10*time.Second)
		if err != nil {
			log.Printf("netlab cat %s: %v", p, err)
			continue
		}
		var meta map[string]any
		if err := json.Unmarshal([]byte(content), &meta); err != nil {
			log.Printf("netlab metadata parse %s: %v", p, err)
			continue
		}
		meta["metadata_path"] = p
		meta["lab_id"] = extractLabIDFromMetadataPath(netlabCfg.StateRoot, p)
		labs = append(labs, meta)
	}
	labsJSON, err := toJSONMapSlice(labs)
	if err != nil {
		log.Printf("netlab labs encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode labs").Err()
	}

	return &NetlabLabsResponse{
		User:      user.Username,
		Runner:    resolvedName,
		StateRoot: netlabCfg.StateRoot,
		Labs:      labsJSON,
	}, nil
}

// ListNetlabLabsV1 returns Netlab labs metadata (v1 alias).
//
//encore:api auth method=GET path=/api/v1/netlab/labs
func (s *Service) ListNetlabLabsV1(ctx context.Context, params *NetlabLabsParams) (*NetlabLabsResponse, error) {
	return s.ListNetlabLabs(ctx, params)
}

// GetNetlabLab returns metadata for a specific Netlab lab.
//
//encore:api auth method=GET path=/api/netlab/labs/:id
func (s *Service) GetNetlabLab(ctx context.Context, id string, params *NetlabLabParams) (*NetlabLabResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	labID := strings.TrimSpace(id)
	if labID == "" || strings.Contains(labID, "..") || strings.ContainsAny(labID, "/\\") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid lab id").Err()
	}
	serverName := ""
	projectID := ""
	if params != nil {
		serverName = strings.TrimSpace(params.NetlabServer)
		projectID = strings.TrimSpace(params.ProjectID)
	}
	if projectID != "" {
		if pid, err := strconv.Atoi(projectID); err == nil && pid > 0 {
			if projects, err := s.projectStore.load(); err == nil {
				for _, p := range projects {
					if p.SemaphoreProjectID != pid {
						continue
					}
					if projectAccessLevelForClaims(s.cfg, p, claims) == "none" {
						return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
					}
					if serverName == "" && strings.TrimSpace(p.NetlabServer) != "" {
						serverName = strings.TrimSpace(p.NetlabServer)
					}
					break
				}
			}
		}
	}
	server, resolvedName := resolveNetlabServer(s.cfg, serverName)
	if server == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab runner is not configured").Err()
	}
	netlabCfg := netlabConfigFromServer(*server, s.cfg.Netlab)

	client, err := dialSSH(netlabCfg)
	if err != nil {
		log.Printf("netlab ssh dial: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach netlab runner").Err()
	}
	defer client.Close()

	path := fmt.Sprintf("%s/%s/metadata.json", netlabCfg.StateRoot, labID)
	content, err := runSSHCommand(client, fmt.Sprintf("cat %q", path), 10*time.Second)
	if err != nil {
		log.Printf("netlab cat %s: %v", path, err)
		return nil, errs.B().Code(errs.NotFound).Msg("lab not found").Err()
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(content), &meta); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("invalid lab metadata").Err()
	}
	meta["metadata_path"] = path
	meta["lab_id"] = labID
	labJSON, err := toJSONMap(meta)
	if err != nil {
		log.Printf("netlab lab encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode lab").Err()
	}
	return &NetlabLabResponse{
		User:   user.Username,
		Runner: resolvedName,
		Lab:    labJSON,
	}, nil
}

// GetNetlabLabV1 returns metadata for a specific Netlab lab (v1 alias).
//
//encore:api auth method=GET path=/api/v1/netlab/labs/:id
func (s *Service) GetNetlabLabV1(ctx context.Context, id string, params *NetlabLabParams) (*NetlabLabResponse, error) {
	return s.GetNetlabLab(ctx, id, params)
}
