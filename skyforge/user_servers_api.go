package skyforge

import (
	"context"
	"net/url"
	"strings"

	"encore.dev/beta/errs"
)

type UserNetlabServerConfig struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	APIURL      string `json:"apiUrl"`
	APIInsecure bool   `json:"apiInsecure"`
	APIUser     string `json:"apiUser,omitempty"`
	APIPassword string `json:"apiPassword,omitempty"`
	APIToken    string `json:"apiToken,omitempty"`
	HasPassword bool   `json:"hasPassword,omitempty"`
}

type UserNetlabServersResponse struct {
	Servers []UserNetlabServerConfig `json:"servers"`
}

// ListUserNetlabServers returns the current user's configured Netlab API endpoints.
//
//encore:api auth method=GET path=/api/user/netlab/servers
func (s *Service) ListUserNetlabServers(ctx context.Context) (*UserNetlabServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	out := []UserNetlabServerConfig{}
	if s.db != nil {
		rows, err := listUserNetlabServers(ctx, s.db, s.box, user.Username)
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
	return &UserNetlabServersResponse{Servers: out}, nil
}

// UpsertUserNetlabServer creates or updates a user-scoped Netlab API endpoint.
//
//encore:api auth method=PUT path=/api/user/netlab/servers
func (s *Service) UpsertUserNetlabServer(ctx context.Context, payload *UserNetlabServerConfig) (*UserNetlabServerConfig, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
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
	rec := userNetlabServer{
		ID:          strings.TrimSpace(payload.ID),
		Username:    user.Username,
		Name:        name,
		APIURL:      apiURL,
		APIInsecure: payload.APIInsecure,
		APIUser:     strings.TrimSpace(payload.APIUser),
		APIPassword: strings.TrimSpace(payload.APIPassword),
		APIToken:    strings.TrimSpace(payload.APIToken),
	}
	out, err := upsertUserNetlabServer(ctx, s.db, s.box, rec)
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

// DeleteUserNetlabServer deletes a user-scoped Netlab server.
//
//encore:api auth method=DELETE path=/api/user/netlab/servers/:serverID
func (s *Service) DeleteUserNetlabServer(ctx context.Context, serverID string) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteUserNetlabServer(ctx, s.db, user.Username, serverID)
}

type UserEveServerConfig struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name"`
	APIURL        string `json:"apiUrl"`
	WebURL        string `json:"webUrl,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	APIUser       string `json:"apiUser,omitempty"`
	APIPassword   string `json:"apiPassword,omitempty"`
	HasPassword   bool   `json:"hasPassword,omitempty"`
	SSHHost       string `json:"sshHost,omitempty"`
	SSHUser       string `json:"sshUser,omitempty"`
	SSHKey        string `json:"sshKey,omitempty"`
	HasSSHKey     bool   `json:"hasSshKey,omitempty"`
}

type UserEveServersResponse struct {
	Servers []UserEveServerConfig `json:"servers"`
}

// ListUserEveServers returns the current user's configured EVE-NG API endpoints.
//
//encore:api auth method=GET path=/api/user/eve/servers
func (s *Service) ListUserEveServers(ctx context.Context) (*UserEveServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	out := []UserEveServerConfig{}
	if s.db != nil {
		rows, err := listUserEveServers(ctx, s.db, s.box, user.Username)
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
					SSHHost:       rec.SSHHost,
					SSHUser:       rec.SSHUser,
					HasSSHKey:     strings.TrimSpace(rec.SSHKey) != "",
				})
			}
		}
	}
	return &UserEveServersResponse{Servers: out}, nil
}

// UpsertUserEveServer creates or updates a user-scoped EVE-NG server.
//
//encore:api auth method=PUT path=/api/user/eve/servers
func (s *Service) UpsertUserEveServer(ctx context.Context, payload *UserEveServerConfig) (*UserEveServerConfig, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
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
	rec := userEveServer{
		ID:            strings.TrimSpace(payload.ID),
		Username:      user.Username,
		Name:          name,
		APIURL:        apiURL,
		WebURL:        webURL,
		SkipTLSVerify: payload.SkipTLSVerify,
		APIUser:       strings.TrimSpace(payload.APIUser),
		APIPassword:   strings.TrimSpace(payload.APIPassword),
		SSHHost:       strings.TrimSpace(payload.SSHHost),
		SSHUser:       strings.TrimSpace(payload.SSHUser),
		SSHKey:        strings.TrimSpace(payload.SSHKey),
	}
	out, err := upsertUserEveServer(ctx, s.db, s.box, rec)
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
		SSHHost:       out.SSHHost,
		SSHUser:       out.SSHUser,
		HasSSHKey:     strings.TrimSpace(out.SSHKey) != "",
	}, nil
}

// DeleteUserEveServer deletes a user-scoped EVE server.
//
//encore:api auth method=DELETE path=/api/user/eve/servers/:serverID
func (s *Service) DeleteUserEveServer(ctx context.Context, serverID string) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteUserEveServer(ctx, s.db, user.Username, serverID)
}

type UserContainerlabServerConfig struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	APIURL      string `json:"apiUrl"`
	APIInsecure bool   `json:"apiInsecure"`
	APIUser     string `json:"apiUser,omitempty"`
	APIPassword string `json:"apiPassword,omitempty"`
	APIToken    string `json:"apiToken,omitempty"`
	HasPassword bool   `json:"hasPassword,omitempty"`
}

type UserContainerlabServersResponse struct {
	Servers []UserContainerlabServerConfig `json:"servers"`
}

// ListUserContainerlabServers returns the current user's configured Containerlab BYOL endpoints.
//
//encore:api auth method=GET path=/api/user/containerlab/servers
func (s *Service) ListUserContainerlabServers(ctx context.Context) (*UserContainerlabServersResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	out := []UserContainerlabServerConfig{}
	if s.db != nil {
		rows, err := listUserContainerlabServers(ctx, s.db, s.box, user.Username)
		if err == nil {
			for _, rec := range rows {
				out = append(out, UserContainerlabServerConfig{
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
	return &UserContainerlabServersResponse{Servers: out}, nil
}

// UpsertUserContainerlabServer creates or updates a user-scoped Containerlab endpoint.
//
//encore:api auth method=PUT path=/api/user/containerlab/servers
func (s *Service) UpsertUserContainerlabServer(ctx context.Context, payload *UserContainerlabServerConfig) (*UserContainerlabServerConfig, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
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
	rec := userContainerlabServer{
		ID:          strings.TrimSpace(payload.ID),
		Username:    user.Username,
		Name:        name,
		APIURL:      apiURL,
		APIInsecure: payload.APIInsecure,
		APIUser:     strings.TrimSpace(payload.APIUser),
		APIPassword: strings.TrimSpace(payload.APIPassword),
		APIToken:    strings.TrimSpace(payload.APIToken),
	}
	out, err := upsertUserContainerlabServer(ctx, s.db, s.box, rec)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save containerlab server").Err()
	}
	return &UserContainerlabServerConfig{
		ID:          out.ID,
		Name:        out.Name,
		APIURL:      out.APIURL,
		APIInsecure: out.APIInsecure,
		APIUser:     out.APIUser,
		HasPassword: strings.TrimSpace(out.APIPassword) != "" || strings.TrimSpace(out.APIToken) != "",
	}, nil
}

// DeleteUserContainerlabServer deletes a user-scoped Containerlab server.
//
//encore:api auth method=DELETE path=/api/user/containerlab/servers/:serverID
func (s *Service) DeleteUserContainerlabServer(ctx context.Context, serverID string) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	return deleteUserContainerlabServer(ctx, s.db, user.Username, serverID)
}
