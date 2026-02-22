package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserScopeForwardConfigResponse struct {
	Configured  bool   `json:"configured"`
	BaseURL     string `json:"baseUrl"`
	Username    string `json:"username,omitempty"`
	CollectorID string `json:"collectorId,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	HasJumpKey  bool   `json:"hasJumpPrivateKey"`
	HasJumpCert bool   `json:"hasJumpCert"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

type UserScopeForwardConfigRequest struct {
	BaseURL           string `json:"baseUrl"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	CollectorID       string `json:"collectorId"`
	CollectorUsername string `json:"collectorUsername"`
	JumpPrivateKey    string `json:"jumpPrivateKey"`
	JumpCert          string `json:"jumpCert"`
}

type UserScopeForwardCollector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type UserScopeForwardCollectorsResponse struct {
	Collectors []UserScopeForwardCollector `json:"collectors"`
}

type UserScopeForwardCollectorCreateResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthorizationKey string `json:"authorizationKey"`
}

const defaultForwardBaseURL = "https://fwd.app"

// GetUserScopeForwardConfig returns Forward Networks credentials for a user scope.
//
//encore:api auth method=GET path=/api/users/:id/integrations/forward
func (s *Service) GetUserScopeForwardConfig(ctx context.Context, id string) (*UserScopeForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserScopeForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userScope.ID)
	if err != nil {
		log.Printf("forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
	}
	if rec == nil {
		return &UserScopeForwardConfigResponse{
			Configured:  false,
			BaseURL:     defaultForwardBaseURL,
			HasPassword: false,
			HasJumpKey:  false,
			HasJumpCert: false,
		}, nil
	}
	updatedAt := ""
	if !rec.UpdatedAt.IsZero() {
		updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	baseURL := strings.TrimSpace(rec.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	return &UserScopeForwardConfigResponse{
		Configured:  baseURL != "" && rec.Username != "" && rec.Password != "",
		BaseURL:     baseURL,
		Username:    rec.Username,
		CollectorID: rec.CollectorID,
		HasPassword: rec.Password != "",
		HasJumpKey:  strings.TrimSpace(rec.JumpPrivateKey) != "",
		HasJumpCert: strings.TrimSpace(rec.JumpCert) != "",
		UpdatedAt:   updatedAt,
	}, nil
}

// PutUserScopeForwardConfig stores Forward Networks credentials for a user scope.
//
//encore:api auth method=PUT path=/api/users/:id/integrations/forward
func (s *Service) PutUserScopeForwardConfig(ctx context.Context, id string, req *UserScopeForwardConfigRequest) (*UserScopeForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	username := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)
	collectorID := strings.TrimSpace(req.CollectorID)
	collectorUser := strings.TrimSpace(req.CollectorUsername)
	jumpKey := strings.TrimSpace(req.JumpPrivateKey)
	jumpCert := strings.TrimSpace(req.JumpCert)

	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current, err := getUserScopeForwardCredentials(ctx, s.db, box, pc.userScope.ID)
	if err != nil {
		log.Printf("forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
	}

	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	if password == "" && current != nil {
		password = current.Password
	}
	if password == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("password is required").Err()
	}
	if current != nil {
		if jumpKey == "" {
			jumpKey = current.JumpPrivateKey
		}
		if jumpCert == "" {
			jumpCert = current.JumpCert
		}
	}

	cfg := forwardCredentials{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
	}
	client, err := newForwardClient(cfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("Forward authentication failed").Err()
	}
	if collectorID != "" && collectorUser == "" {
		for _, collector := range collectors {
			if strings.EqualFold(strings.TrimSpace(collector.ID), collectorID) {
				collectorUser = strings.TrimSpace(collector.Username)
				break
			}
		}
		if collectorUser == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown Forward collector").Err()
		}
	}

	if err := putUserScopeForwardCredentials(ctx, s.db, box, pc.userScope.ID, forwardCredentials{
		BaseURL:        baseURL,
		Username:       username,
		Password:       password,
		CollectorID:    collectorID,
		CollectorUser:  collectorUser,
		JumpPrivateKey: jumpKey,
		JumpCert:       jumpCert,
	}); err != nil {
		log.Printf("forward put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store Forward config").Err()
	}

	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("baseUrl=%s username=%s", baseURL, username)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user_scope.forward.set", pc.userScope.ID, details)
	}

	return &UserScopeForwardConfigResponse{
		Configured:  true,
		BaseURL:     baseURL,
		Username:    username,
		CollectorID: collectorID,
		HasPassword: true,
		HasJumpKey:  jumpKey != "",
		HasJumpCert: jumpCert != "",
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetUserScopeForwardCollectors lists available Forward collectors for the user scope.
//
//encore:api auth method=GET path=/api/users/:id/integrations/forward/collectors
func (s *Service) GetUserScopeForwardCollectors(ctx context.Context, id string) (*UserScopeForwardCollectorsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	forwardCfg, err := s.forwardConfigForUserScope(ctx, pc.userScope.ID)
	if err != nil || forwardCfg == nil {
		return &UserScopeForwardCollectorsResponse{Collectors: []UserScopeForwardCollector{}}, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collectors").Err()
	}
	out := make([]UserScopeForwardCollector, 0, len(collectors))
	for _, collector := range collectors {
		out = append(out, UserScopeForwardCollector{
			ID:       strings.TrimSpace(collector.ID),
			Name:     strings.TrimSpace(collector.Name),
			Username: strings.TrimSpace(collector.Username),
		})
	}
	return &UserScopeForwardCollectorsResponse{Collectors: out}, nil
}

// CreateUserScopeForwardCollector creates a Forward collector for the user scope.
//
//encore:api auth method=POST path=/api/users/:id/integrations/forward/collectors
func (s *Service) CreateUserScopeForwardCollector(ctx context.Context, id string) (*UserScopeForwardCollectorCreateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	forwardCfg, err := s.forwardConfigForUserScope(ctx, pc.userScope.ID)
	if err != nil || forwardCfg == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("Forward credentials required").Err()
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	name := strings.TrimSpace(pc.userScope.Slug)
	if name == "" {
		name = strings.TrimSpace(pc.userScope.ID)
	}
	collector, err := forwardCreateCollector(ctx, client, name)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
	}
	return &UserScopeForwardCollectorCreateResponse{
		ID:               strings.TrimSpace(collector.ID),
		Name:             strings.TrimSpace(collector.Name),
		Username:         strings.TrimSpace(collector.Username),
		AuthorizationKey: strings.TrimSpace(collector.AuthorizationKey),
	}, nil
}

// DeleteUserScopeForwardConfig removes Forward Networks credentials for a user scope.
//
//encore:api auth method=DELETE path=/api/users/:id/integrations/forward
func (s *Service) DeleteUserScopeForwardConfig(ctx context.Context, id string) (*UserScopeForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := deleteUserScopeForwardCredentials(ctx, s.db, pc.userScope.ID); err != nil {
		log.Printf("forward delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user_scope.forward.clear", pc.userScope.ID, "")
	}
	return &UserScopeForwardConfigResponse{
		Configured: false,
		BaseURL:    defaultForwardBaseURL,
	}, nil
}
