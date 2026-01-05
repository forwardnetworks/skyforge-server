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
	WorkspaceID  string `query:"workspace_id" encore:"optional"`
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
	WorkspaceID  string `query:"workspace_id" encore:"optional"`
	NetlabServer string `query:"netlab_server" encore:"optional"`
}

type NetlabLabsResponse struct {
	User      string    `json:"user"`
	Runner    string    `json:"runner"`
	StateRoot string    `json:"state_root"`
	Labs      []JSONMap `json:"labs"`
}

type NetlabLabParams struct {
	WorkspaceID  string `query:"workspace_id" encore:"optional"`
	NetlabServer string `query:"netlab_server" encore:"optional"`
}

type NetlabLabResponse struct {
	User   string  `json:"user"`
	Runner string  `json:"runner"`
	Lab    JSONMap `json:"lab"`
}

type NetlabDefaultsParams struct {
	WorkspaceID  string `query:"workspace_id" encore:"optional"`
	NetlabServer string `query:"netlab_server" encore:"optional"`
}

type NetlabDefaultsResponse struct {
	User   string `json:"user"`
	Runner string `json:"runner"`
	Output string `json:"output"`
}

// GetLabsRunning returns running labs across providers (public).
//
//encore:api public method=GET path=/api/labs/running
func (s *Service) GetLabsRunning(ctx context.Context, params *LabsRunningParams) (*LabsRunningResponse, error) {
	labsRunningRequests.Add(1)
	provider := ""
	eveServer := ""
	netlabServer := ""
	workspaceID := ""
	if params != nil {
		provider = strings.TrimSpace(strings.ToLower(params.Provider))
		eveServer = strings.TrimSpace(params.EveServer)
		netlabServer = strings.TrimSpace(params.NetlabServer)
		workspaceID = strings.TrimSpace(params.WorkspaceID)
	}
	if workspaceID != "" && eveServer == "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil && strings.TrimSpace(workspace.EveServer) != "" {
				eveServer = strings.TrimSpace(workspace.EveServer)
			}
		}
	}
	if workspaceID != "" && netlabServer == "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil && strings.TrimSpace(workspace.NetlabServer) != "" {
				netlabServer = strings.TrimSpace(workspace.NetlabServer)
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
	workspaceID := ""
	if params != nil {
		provider = strings.TrimSpace(strings.ToLower(params.Provider))
		eveServer = strings.TrimSpace(params.EveServer)
		netlabServer = strings.TrimSpace(params.NetlabServer)
		workspaceID = strings.TrimSpace(params.WorkspaceID)
	}

	ownerOverride := ""
	if workspaceID != "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil {
				if eveServer == "" && strings.TrimSpace(workspace.EveServer) != "" {
					eveServer = strings.TrimSpace(workspace.EveServer)
				}
				if netlabServer == "" && strings.TrimSpace(workspace.NetlabServer) != "" {
					netlabServer = strings.TrimSpace(workspace.NetlabServer)
				}
				if workspaceAccessLevelForClaims(s.cfg, *workspace, claims) == "none" {
					labsErrors.Add(1)
					return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
				}
				ownerOverride = workspacePrimaryOwner(*workspace)
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

// GetNetlabDefaults returns the current netlab defaults from a runner.
//
//encore:api auth method=GET path=/api/netlab/defaults
func (s *Service) GetNetlabDefaults(ctx context.Context, params *NetlabDefaultsParams) (*NetlabDefaultsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	serverName := ""
	workspaceID := ""
	if params != nil {
		serverName = strings.TrimSpace(params.NetlabServer)
		workspaceID = strings.TrimSpace(params.WorkspaceID)
	}
	if workspaceID != "" && serverName == "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil && strings.TrimSpace(workspace.NetlabServer) != "" {
				serverName = strings.TrimSpace(workspace.NetlabServer)
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
		log.Printf("netlab defaults ssh dial: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach netlab runner").Err()
	}
	defer client.Close()

	output, err := runSSHCommand(client, "netlab show defaults", 15*time.Second)
	if err != nil {
		log.Printf("netlab defaults cmd: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to read netlab defaults").Err()
	}

	return &NetlabDefaultsResponse{
		User:   user.Username,
		Runner: resolvedName,
		Output: strings.TrimSpace(output),
	}, nil
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
	workspaceID := ""
	if params != nil {
		serverName = strings.TrimSpace(params.NetlabServer)
		workspaceID = strings.TrimSpace(params.WorkspaceID)
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 100 {
				limit = v
			}
		}
	}
	if workspaceID != "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil {
				if workspaceAccessLevelForClaims(s.cfg, *workspace, claims) == "none" {
					return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
				}
				if serverName == "" && strings.TrimSpace(workspace.NetlabServer) != "" {
					serverName = strings.TrimSpace(workspace.NetlabServer)
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
	workspaceID := ""
	if params != nil {
		serverName = strings.TrimSpace(params.NetlabServer)
		workspaceID = strings.TrimSpace(params.WorkspaceID)
	}
	if workspaceID != "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil {
				if workspaceAccessLevelForClaims(s.cfg, *workspace, claims) == "none" {
					return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
				}
				if serverName == "" && strings.TrimSpace(workspace.NetlabServer) != "" {
					serverName = strings.TrimSpace(workspace.NetlabServer)
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
