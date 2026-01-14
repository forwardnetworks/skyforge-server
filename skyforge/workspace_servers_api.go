package skyforge

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"encore.dev/beta/errs"
)

type WorkspaceServerRef struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Scope string `json:"scope"` // global|workspace
}

type WorkspaceNetlabServerConfig struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	APIURL      string `json:"apiUrl"`
	APIInsecure bool   `json:"apiInsecure"`
	APIToken    string `json:"apiToken,omitempty"`
}

type WorkspaceNetlabServersResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Servers     []WorkspaceServerRef `json:"servers"`
}

type WorkspaceEveServerConfig struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name"`
	APIURL        string `json:"apiUrl"`
	WebURL        string `json:"webUrl,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	SSHHost       string `json:"sshHost,omitempty"`
	SSHUser       string `json:"sshUser,omitempty"`
	SSHKey        string `json:"sshKey,omitempty"`
}

type WorkspaceEveServersResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Servers     []WorkspaceServerRef `json:"servers"`
}

func requireWorkspaceOwner(ctx context.Context, s *Service, workspaceID string) (*workspaceContext, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, workspaceID)
	if err != nil {
		return nil, err
	}
	access := workspaceAccessLevelForClaims(s.cfg, pc.workspace, pc.claims)
	if access != "owner" && access != "admin" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return pc, nil
}

func validateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return "", fmt.Errorf("invalid url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("url must be http(s)")
	}
	return strings.TrimRight(raw, "/"), nil
}

// ListWorkspaceNetlabServers returns the configured Netlab API endpoints for this workspace,
// including global defaults.
//
//encore:api auth method=GET path=/api/workspaces/:id/netlab/servers
func (s *Service) ListWorkspaceNetlabServers(ctx context.Context, id string) (*WorkspaceNetlabServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if workspaceAccessLevelForClaims(s.cfg, pc.workspace, pc.claims) == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	out := []WorkspaceServerRef{}
	if len(s.cfg.NetlabServers) == 0 && len(s.cfg.EveServers) > 0 {
		for _, eve := range s.cfg.EveServers {
			name := strings.TrimSpace(eve.Name)
			if name == "" {
				continue
			}
			out = append(out, WorkspaceServerRef{Value: name, Label: name, Scope: "global"})
		}
	} else {
		for _, server := range s.cfg.NetlabServers {
			name := strings.TrimSpace(server.Name)
			if name == "" {
				continue
			}
			out = append(out, WorkspaceServerRef{Value: name, Label: name, Scope: "global"})
		}
	}

	if s.db != nil {
		rows, err := listWorkspaceNetlabServers(ctx, s.db, s.box, id)
		if err == nil {
			for _, rec := range rows {
				label := rec.Name
				if label == "" {
					label = rec.APIURL
				}
				out = append(out, WorkspaceServerRef{Value: workspaceServerRef(rec.ID), Label: label, Scope: "workspace"})
			}
		}
	}

	return &WorkspaceNetlabServersResponse{WorkspaceID: id, Servers: out}, nil
}

// UpsertWorkspaceNetlabServer creates or updates a workspace-scoped Netlab API endpoint.
//
//encore:api auth method=PUT path=/api/workspaces/:id/netlab/servers
func (s *Service) UpsertWorkspaceNetlabServer(ctx context.Context, id string, payload *WorkspaceNetlabServerConfig) (*WorkspaceNetlabServerConfig, error) {
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	_, err := requireWorkspaceOwner(ctx, s, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	apiURL, err := validateURL(payload.APIURL)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	rec := workspaceNetlabServer{
		ID:          strings.TrimSpace(payload.ID),
		WorkspaceID: id,
		Name:        name,
		APIURL:      apiURL,
		APIInsecure: payload.APIInsecure,
		APIToken:    strings.TrimSpace(payload.APIToken),
	}
	out, err := upsertWorkspaceNetlabServer(ctx, s.db, s.box, rec)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save netlab server").Err()
	}
	return &WorkspaceNetlabServerConfig{
		ID:          out.ID,
		Name:        out.Name,
		APIURL:      out.APIURL,
		APIInsecure: out.APIInsecure,
	}, nil
}

// DeleteWorkspaceNetlabServer deletes a workspace-scoped Netlab server.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/netlab/servers/:serverID
func (s *Service) DeleteWorkspaceNetlabServer(ctx context.Context, id, serverID string) error {
	_, err := requireWorkspaceOwner(ctx, s, id)
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteWorkspaceNetlabServer(ctx, s.db, id, serverID)
}

// ListWorkspaceEveServers returns configured EVE-NG servers for a workspace (global + custom).
//
//encore:api auth method=GET path=/api/workspaces/:id/eve/servers
func (s *Service) ListWorkspaceEveServers(ctx context.Context, id string) (*WorkspaceEveServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if workspaceAccessLevelForClaims(s.cfg, pc.workspace, pc.claims) == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	out := []WorkspaceServerRef{}
	for _, server := range s.cfg.EveServers {
		name := strings.TrimSpace(server.Name)
		if name == "" {
			continue
		}
		out = append(out, WorkspaceServerRef{Value: name, Label: name, Scope: "global"})
	}

	if s.db != nil {
		rows, err := listWorkspaceEveServers(ctx, s.db, s.box, id)
		if err == nil {
			for _, rec := range rows {
				label := rec.Name
				if label == "" {
					label = rec.APIURL
				}
				out = append(out, WorkspaceServerRef{Value: workspaceServerRef(rec.ID), Label: label, Scope: "workspace"})
			}
		}
	}

	return &WorkspaceEveServersResponse{WorkspaceID: id, Servers: out}, nil
}

// UpsertWorkspaceEveServer creates or updates a workspace-scoped EVE-NG server.
//
//encore:api auth method=PUT path=/api/workspaces/:id/eve/servers
func (s *Service) UpsertWorkspaceEveServer(ctx context.Context, id string, payload *WorkspaceEveServerConfig) (*WorkspaceEveServerConfig, error) {
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	_, err := requireWorkspaceOwner(ctx, s, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	apiURL, err := validateURL(payload.APIURL)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	webURL := strings.TrimSpace(payload.WebURL)
	if webURL != "" {
		if webURL, err = validateURL(webURL); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid webUrl").Err()
		}
	}
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	rec := workspaceEveServer{
		ID:            strings.TrimSpace(payload.ID),
		WorkspaceID:   id,
		Name:          name,
		APIURL:        apiURL,
		WebURL:        webURL,
		SkipTLSVerify: payload.SkipTLSVerify,
		SSHHost:       strings.TrimSpace(payload.SSHHost),
		SSHUser:       strings.TrimSpace(payload.SSHUser),
		SSHKey:        strings.TrimSpace(payload.SSHKey),
	}
	out, err := upsertWorkspaceEveServer(ctx, s.db, s.box, rec)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save eve server").Err()
	}
	return &WorkspaceEveServerConfig{
		ID:            out.ID,
		Name:          out.Name,
		APIURL:        out.APIURL,
		WebURL:        out.WebURL,
		SkipTLSVerify: out.SkipTLSVerify,
		SSHHost:       out.SSHHost,
		SSHUser:       out.SSHUser,
	}, nil
}

// DeleteWorkspaceEveServer deletes a workspace-scoped EVE server.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/eve/servers/:serverID
func (s *Service) DeleteWorkspaceEveServer(ctx context.Context, id, serverID string) error {
	_, err := requireWorkspaceOwner(ctx, s, id)
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteWorkspaceEveServer(ctx, s.db, id, serverID)
}

