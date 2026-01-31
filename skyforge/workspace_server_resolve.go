package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

func (s *Service) resolveWorkspaceNetlabServerConfig(ctx context.Context, workspaceID string, serverRef string) (*NetlabServerConfig, error) {
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("workspace id required").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server is required (configure a Netlab server in workspace settings)").Err()
	}
	serverID, ok := parseWorkspaceServerRef(serverRef)
	if !ok {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("netlab server must be a workspace server reference (ws:...)").Err()
	}
	rec, err := getWorkspaceNetlabServerByID(ctx, s.db, s.box, workspaceID, serverID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspace netlab server").Err()
	}
	if rec == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("workspace netlab server not found").Err()
	}
	custom := NetlabServerConfig{
		Name:        strings.TrimSpace(rec.Name),
		APIURL:      strings.TrimSpace(rec.APIURL),
		APIInsecure: rec.APIInsecure,
		APIToken:    strings.TrimSpace(rec.APIToken),
		StateRoot:   strings.TrimSpace(s.cfg.Netlab.StateRoot),
	}
	custom = normalizeNetlabServer(custom, s.cfg.Netlab)
	return &custom, nil
}

func (s *Service) resolveNetlabServerConfig(ctx context.Context, pc *workspaceContext, serverRef string) (*NetlabServerConfig, error) {
	if pc == nil || pc.claims == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("workspace context unavailable").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server is required").Err()
	}

	if strings.HasPrefix(strings.ToLower(serverRef), userServerRefPrefix) {
		if !pc.workspace.AllowCustomNetlabServers {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("custom netlab servers are disabled for this workspace").Err()
		}
		serverID, ok := parseUserServerRef(serverRef)
		if !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid user netlab server reference (user:...)").Err()
		}
		if s == nil || s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getUserNetlabServerByID(ctx, s.db, s.box, pc.claims.Username, serverID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user netlab server").Err()
		}
		if rec == nil {
			return nil, errs.B().Code(errs.NotFound).Msg("user netlab server not found").Err()
		}
		custom := NetlabServerConfig{
			Name:        strings.TrimSpace(rec.Name),
			APIURL:      strings.TrimSpace(rec.APIURL),
			APIInsecure: rec.APIInsecure,
			APIToken:    strings.TrimSpace(rec.APIToken),
			StateRoot:   strings.TrimSpace(s.cfg.Netlab.StateRoot),
		}
		custom = normalizeNetlabServer(custom, s.cfg.Netlab)
		return &custom, nil
	}

	if _, ok := parseWorkspaceServerRef(serverRef); ok {
		return s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, serverRef)
	}
	return nil, errs.B().Code(errs.InvalidArgument).Msg("netlab server must be a workspace reference (ws:...) or user reference (user:...)").Err()
}

func (s *Service) resolveContainerlabServerConfig(ctx context.Context, pc *workspaceContext, serverRef string) (*NetlabServerConfig, error) {
	if pc == nil || pc.claims == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("workspace context unavailable").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab server is required").Err()
	}

	if strings.HasPrefix(strings.ToLower(serverRef), userServerRefPrefix) {
		if !pc.workspace.AllowCustomContainerlabServers {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("custom containerlab servers are disabled for this workspace").Err()
		}
		serverID, ok := parseUserServerRef(serverRef)
		if !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid user containerlab server reference (user:...)").Err()
		}
		if s == nil || s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getUserContainerlabServerByID(ctx, s.db, s.box, pc.claims.Username, serverID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user containerlab server").Err()
		}
		if rec == nil {
			return nil, errs.B().Code(errs.NotFound).Msg("user containerlab server not found").Err()
		}
		custom := NetlabServerConfig{
			Name:        strings.TrimSpace(rec.Name),
			APIURL:      strings.TrimSpace(rec.APIURL),
			APIInsecure: rec.APIInsecure,
			APIToken:    strings.TrimSpace(rec.APIToken),
			StateRoot:   strings.TrimSpace(s.cfg.Netlab.StateRoot),
		}
		custom = normalizeNetlabServer(custom, s.cfg.Netlab)
		return &custom, nil
	}

	if _, ok := parseWorkspaceServerRef(serverRef); ok {
		return s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, serverRef)
	}
	return nil, errs.B().Code(errs.InvalidArgument).Msg("containerlab server must be a workspace reference (ws:...) or user reference (user:...)").Err()
}

func (s *Service) checkWorkspaceNetlabHealth(ctx context.Context, workspaceID string, serverRef string) error {
	server, err := s.resolveWorkspaceNetlabServerConfig(ctx, workspaceID, serverRef)
	if err != nil {
		return err
	}
	apiURL := strings.TrimRight(strings.TrimSpace(server.APIURL), "/")
	if apiURL == "" {
		return errs.B().Code(errs.FailedPrecondition).Msg("netlab apiUrl is required").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, body, err := netlabAPIGet(ctxReq, apiURL+"/healthz", server.APIInsecure, netlabAPIAuth{BearerToken: strings.TrimSpace(server.APIToken)})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errs.B().Code(errs.Unavailable).Msgf("netlab unhealthy: %s", strings.TrimSpace(string(body))).Err()
	}
	return nil
}
