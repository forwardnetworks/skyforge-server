package skyforge

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

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
	APIUser     string `json:"apiUser,omitempty"`
	APIPassword string `json:"apiPassword,omitempty"`
	APIToken    string `json:"apiToken,omitempty"`
	HasPassword bool   `json:"hasPassword,omitempty"`
}

type WorkspaceNetlabServersResponse struct {
	WorkspaceID string                        `json:"workspaceId"`
	Servers     []WorkspaceNetlabServerConfig `json:"servers"`
}

type WorkspaceServerHealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
	Error  string `json:"error,omitempty"`
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

// ListWorkspaceNetlabServers returns the configured Netlab API endpoints for this workspace.
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

	out := []WorkspaceNetlabServerConfig{}
	if s.db != nil {
		rows, err := listWorkspaceNetlabServers(ctx, s.db, s.box, id)
		if err == nil {
			for _, rec := range rows {
				out = append(out, WorkspaceNetlabServerConfig{
					ID:          rec.ID,
					Name:        rec.Name,
					APIURL:      rec.APIURL,
					APIInsecure: rec.APIInsecure,
					APIUser:     rec.APIUser,
					HasPassword: strings.TrimSpace(rec.APIPassword) != "" || strings.TrimSpace(rec.APIToken) != "",
				})
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
		APIUser:     strings.TrimSpace(payload.APIUser),
		APIPassword: strings.TrimSpace(payload.APIPassword),
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
		APIUser:     out.APIUser,
		HasPassword: strings.TrimSpace(out.APIPassword) != "" || strings.TrimSpace(out.APIToken) != "",
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

type WorkspaceEveServerConfig struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name"`
	APIURL        string `json:"apiUrl"`
	WebURL        string `json:"webUrl,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	APIUser       string `json:"apiUser,omitempty"`
	APIPassword   string `json:"apiPassword,omitempty"`
	HasPassword   bool   `json:"hasPassword,omitempty"`
}

type WorkspaceEveServersResponse struct {
	WorkspaceID string                     `json:"workspaceId"`
	Servers     []WorkspaceEveServerConfig `json:"servers"`
}

// ListWorkspaceEveServers returns the configured EVE-NG API endpoints for this workspace.
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

	out := []WorkspaceEveServerConfig{}
	if s.db != nil {
		rows, err := listWorkspaceEveServers(ctx, s.db, s.box, id)
		if err == nil {
			for _, rec := range rows {
				out = append(out, WorkspaceEveServerConfig{
					ID:            rec.ID,
					Name:          rec.Name,
					APIURL:        rec.APIURL,
					WebURL:        rec.WebURL,
					SkipTLSVerify: rec.SkipTLSVerify,
					APIUser:       rec.APIUser,
					HasPassword:   strings.TrimSpace(rec.APIPassword) != "",
				})
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
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	webURL := strings.TrimSpace(payload.WebURL)
	if webURL != "" {
		if parsed, err := validateURL(webURL); err == nil {
			webURL = parsed
		} else {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid webUrl").Err()
		}
	}

	rec := workspaceEveServer{
		ID:            strings.TrimSpace(payload.ID),
		WorkspaceID:   id,
		Name:          name,
		APIURL:        apiURL,
		WebURL:        webURL,
		SkipTLSVerify: payload.SkipTLSVerify,
		APIUser:       strings.TrimSpace(payload.APIUser),
		APIPassword:   strings.TrimSpace(payload.APIPassword),
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
		APIUser:       out.APIUser,
		HasPassword:   strings.TrimSpace(out.APIPassword) != "",
	}, nil
}

// DeleteWorkspaceEveServer deletes a workspace-scoped EVE-NG server.
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

// GetWorkspaceNetlabServerHealth checks the health of a workspace-scoped Netlab API server.
//
//encore:api auth method=GET path=/api/workspaces/:id/netlab/servers/:serverID/health
func (s *Service) GetWorkspaceNetlabServerHealth(ctx context.Context, id, serverID string) (*WorkspaceServerHealthResponse, error) {
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
	if err := s.checkWorkspaceNetlabHealth(ctx, id, workspaceServerRef(serverID)); err != nil {
		return &WorkspaceServerHealthResponse{
			Status: "error",
			Time:   time.Now().UTC().Format(time.RFC3339),
			Error:  sanitizeError(err),
		}, nil
	}
	return &WorkspaceServerHealthResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}
