package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
)

func (s *Service) resolveUserScopeNetlabServerConfig(ctx context.Context, userScopeID string, serverRef string) (*NetlabServerConfig, error) {
	if s == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user id required").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server is required (configure a Netlab server in user settings)").Err()
	}
	serverID, ok := parseUserServerRef(serverRef)
	if !ok {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("netlab server must be a user server reference (user:...)").Err()
	}
	rec, err := getUserNetlabServerByID(ctx, s.db, s.box, userScopeID, serverID)
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

func (s *Service) resolveNetlabServerConfig(ctx context.Context, pc *userContext, serverRef string) (*NetlabServerConfig, error) {
	if pc == nil || pc.claims == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("user context unavailable").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server is required").Err()
	}

	if strings.HasPrefix(strings.ToLower(serverRef), userServerRefPrefix) {
		if !isAdminUser(s.cfg, pc.claims.Username) {
			policy, err := loadGovernancePolicy(ctx, s.db)
			if err != nil {
				return nil, errs.B().Code(errs.Unavailable).Msg("failed to evaluate governance policy").Err()
			}
			if !policy.AllowUserByosNetlabServers {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("user-scoped Netlab BYOS servers are not enabled by governance policy").Err()
			}
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

	return nil, errs.B().Code(errs.InvalidArgument).Msg("netlab server must be a user reference (user:...)").Err()
}

func (s *Service) resolveContainerlabServerConfig(ctx context.Context, pc *userContext, serverRef string) (*NetlabServerConfig, error) {
	if pc == nil || pc.claims == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("user context unavailable").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab server is required").Err()
	}

	if strings.HasPrefix(strings.ToLower(serverRef), userServerRefPrefix) {
		if !isAdminUser(s.cfg, pc.claims.Username) {
			policy, err := loadGovernancePolicy(ctx, s.db)
			if err != nil {
				return nil, errs.B().Code(errs.Unavailable).Msg("failed to evaluate governance policy").Err()
			}
			if !policy.AllowUserByosContainerlabServers {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("user-scoped Containerlab BYOS servers are not enabled by governance policy").Err()
			}
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

	return nil, errs.B().Code(errs.InvalidArgument).Msg("containerlab server must be a user reference (user:...)").Err()
}

func (s *Service) resolveEveServerConfig(ctx context.Context, pc *userContext, serverRef string) (*EveServerConfig, error) {
	if pc == nil || pc.claims == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("user context unavailable").Err()
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng server is required").Err()
	}

	if strings.HasPrefix(strings.ToLower(serverRef), userServerRefPrefix) {
		serverID, ok := parseUserServerRef(serverRef)
		if !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid user eve-ng server reference (user:...)").Err()
		}
		if s == nil || s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getUserEveServerByID(ctx, s.db, s.box, pc.claims.Username, serverID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user eve-ng server").Err()
		}
		if rec == nil {
			return nil, errs.B().Code(errs.NotFound).Msg("user eve-ng server not found").Err()
		}
		return &EveServerConfig{
			Name:          strings.TrimSpace(rec.Name),
			APIURL:        strings.TrimSpace(rec.APIURL),
			WebURL:        strings.TrimSpace(rec.WebURL),
			SkipTLSVerify: rec.SkipTLSVerify,
			APIUser:       strings.TrimSpace(rec.APIUser),
			APIPassword:   strings.TrimSpace(rec.APIPassword),
			SSHHost:       strings.TrimSpace(rec.SSHHost),
			SSHUser:       strings.TrimSpace(rec.SSHUser),
			SSHKey:        strings.TrimSpace(rec.SSHKey),
		}, nil
	}

	return nil, errs.B().Code(errs.InvalidArgument).Msg("eve-ng server must be a user reference (user:...)").Err()
}
