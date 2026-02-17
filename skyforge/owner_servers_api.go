package skyforge

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserServerRef struct {
	Value   string `json:"value"`
	Label   string `json:"label"`
	Context string `json:"context,omitempty"` // global|user
	Legacy  string `json:"-"`                 // legacy internal field
}

type UserOwnerNetlabServersResponse struct {
	OwnerUsername string                   `json:"ownerUsername"`
	Servers       []UserNetlabServerConfig `json:"servers"`
}

type UserOwnerServerHealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
	Error  string `json:"error,omitempty"`
}

func requireOwnerEditor(ctx context.Context, s *Service, ownerID string) (*ownerContext, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, ownerID)
	if err != nil {
		return nil, err
	}
	access := ownerAccessLevelForClaims(s.cfg, pc.context, pc.claims)
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

// Backward-compatible aliases; prefer User* names.
type UserServerHealthResponse = UserOwnerServerHealthResponse

// ListOwnerNetlabServers returns the configured Netlab API endpoints for this user context.
func (s *Service) ListOwnerNetlabServers(ctx context.Context, id string) (*UserOwnerNetlabServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if ownerAccessLevelForClaims(s.cfg, pc.context, pc.claims) == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	out := []UserNetlabServerConfig{}
	if s.db != nil {
		rows, err := listOwnerNetlabServers(ctx, s.db, s.box, id)
		if err == nil {
			for _, rec := range rows {
				out = append(out, UserNetlabServerConfig{
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
	return &UserOwnerNetlabServersResponse{OwnerUsername: id, Servers: out}, nil
}

// UpsertOwnerNetlabServer creates or updates a user-context Netlab API endpoint.
func (s *Service) UpsertOwnerNetlabServer(ctx context.Context, id string, payload *UserNetlabServerConfig) (*UserNetlabServerConfig, error) {
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	_, err := requireOwnerEditor(ctx, s, id)
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
		// UI no longer asks for a name; derive a stable label from the URL.
		if u, err := url.Parse(apiURL); err == nil && u != nil {
			name = strings.TrimSpace(u.Hostname())
		}
		if name == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
		}
	}
	rec := ownerNetlabServer{
		ID:            strings.TrimSpace(payload.ID),
		OwnerUsername: id,
		Name:          name,
		APIURL:        apiURL,
		APIInsecure:   payload.APIInsecure,
		APIUser:       strings.TrimSpace(payload.APIUser),
		APIPassword:   strings.TrimSpace(payload.APIPassword),
		APIToken:      strings.TrimSpace(payload.APIToken),
	}
	out, err := upsertOwnerNetlabServer(ctx, s.db, s.box, rec)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save netlab server").Err()
	}
	return &UserNetlabServerConfig{
		ID:          out.ID,
		Name:        out.Name,
		APIURL:      out.APIURL,
		APIInsecure: out.APIInsecure,
		APIUser:     out.APIUser,
		HasPassword: strings.TrimSpace(out.APIPassword) != "" || strings.TrimSpace(out.APIToken) != "",
	}, nil
}

// DeleteOwnerNetlabServer deletes a user-context Netlab server.
func (s *Service) DeleteOwnerNetlabServer(ctx context.Context, id, serverID string) error {
	_, err := requireOwnerEditor(ctx, s, id)
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteOwnerNetlabServer(ctx, s.db, id, serverID)
}

type UserOwnerEveServersResponse struct {
	OwnerUsername string                `json:"ownerUsername"`
	Servers       []UserEveServerConfig `json:"servers"`
}

// ListOwnerEveServers returns the configured EVE-NG API endpoints for this user context.
func (s *Service) ListOwnerEveServers(ctx context.Context, id string) (*UserOwnerEveServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if ownerAccessLevelForClaims(s.cfg, pc.context, pc.claims) == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	out := []UserEveServerConfig{}
	if s.db != nil {
		rows, err := listOwnerEveServers(ctx, s.db, s.box, id)
		if err == nil {
			for _, rec := range rows {
				out = append(out, UserEveServerConfig{
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

	return &UserOwnerEveServersResponse{OwnerUsername: id, Servers: out}, nil
}

// UpsertOwnerEveServer creates or updates a user-context EVE-NG server.
func (s *Service) UpsertOwnerEveServer(ctx context.Context, id string, payload *UserEveServerConfig) (*UserEveServerConfig, error) {
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	_, err := requireOwnerEditor(ctx, s, id)
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
		if u, err := url.Parse(apiURL); err == nil && u != nil {
			name = strings.TrimSpace(u.Hostname())
		}
		if name == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
		}
	}
	webURL := strings.TrimSpace(payload.WebURL)
	if webURL != "" {
		if parsed, err := validateURL(webURL); err == nil {
			webURL = parsed
		} else {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid webUrl").Err()
		}
	}

	rec := ownerEveServer{
		ID:            strings.TrimSpace(payload.ID),
		OwnerUsername: id,
		Name:          name,
		APIURL:        apiURL,
		WebURL:        webURL,
		SkipTLSVerify: payload.SkipTLSVerify,
		APIUser:       strings.TrimSpace(payload.APIUser),
		APIPassword:   strings.TrimSpace(payload.APIPassword),
	}
	out, err := upsertOwnerEveServer(ctx, s.db, s.box, rec)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save eve server").Err()
	}
	return &UserEveServerConfig{
		ID:            out.ID,
		Name:          out.Name,
		APIURL:        out.APIURL,
		WebURL:        out.WebURL,
		SkipTLSVerify: out.SkipTLSVerify,
		APIUser:       out.APIUser,
		HasPassword:   strings.TrimSpace(out.APIPassword) != "",
	}, nil
}

// DeleteOwnerEveServer deletes a user-context EVE-NG server.
func (s *Service) DeleteOwnerEveServer(ctx context.Context, id, serverID string) error {
	_, err := requireOwnerEditor(ctx, s, id)
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteOwnerEveServer(ctx, s.db, id, serverID)
}

// GetUserNetlabServerHealth checks the health of a user-context Netlab API server.
func (s *Service) GetUserNetlabServerHealth(ctx context.Context, id, serverID string) (*UserOwnerServerHealthResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if ownerAccessLevelForClaims(s.cfg, pc.context, pc.claims) == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if err := s.checkUserNetlabHealth(ctx, id, ownerServerRef(serverID)); err != nil {
		return &UserOwnerServerHealthResponse{
			Status: "error",
			Time:   time.Now().UTC().Format(time.RFC3339),
			Error:  sanitizeError(err),
		}, nil
	}
	return &UserOwnerServerHealthResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}
