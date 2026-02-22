package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type WorkspaceForwardConfigResponse struct {
	Configured  bool   `json:"configured"`
	BaseURL     string `json:"baseUrl"`
	Username    string `json:"username,omitempty"`
	CollectorID string `json:"collectorId,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	HasJumpKey  bool   `json:"hasJumpPrivateKey"`
	HasJumpCert bool   `json:"hasJumpCert"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

type WorkspaceForwardConfigRequest struct {
	BaseURL           string `json:"baseUrl"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	CollectorID       string `json:"collectorId"`
	CollectorUsername string `json:"collectorUsername"`
	JumpPrivateKey    string `json:"jumpPrivateKey"`
	JumpCert          string `json:"jumpCert"`
}

type WorkspaceForwardCollector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type WorkspaceForwardCollectorsResponse struct {
	Collectors []WorkspaceForwardCollector `json:"collectors"`
}

type WorkspaceForwardCollectorCreateResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthorizationKey string `json:"authorizationKey"`
}

const defaultForwardBaseURL = "https://fwd.app"

// GetWorkspaceForwardConfig returns Forward Networks credentials for a workspace.
//
//encore:api auth method=GET path=/api/users/:id/integrations/forward
func (s *Service) GetWorkspaceForwardConfig(ctx context.Context, id string) (*WorkspaceForwardConfigResponse, error) {
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
	rec, err := getWorkspaceForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.workspace.ID)
	if err != nil {
		log.Printf("forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
	}
	if rec == nil {
		return &WorkspaceForwardConfigResponse{
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
	return &WorkspaceForwardConfigResponse{
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

// PutWorkspaceForwardConfig stores Forward Networks credentials for a workspace.
//
//encore:api auth method=PUT path=/api/users/:id/integrations/forward
func (s *Service) PutWorkspaceForwardConfig(ctx context.Context, id string, req *WorkspaceForwardConfigRequest) (*WorkspaceForwardConfigResponse, error) {
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
	current, err := getWorkspaceForwardCredentials(ctx, s.db, box, pc.workspace.ID)
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

	if err := putWorkspaceForwardCredentials(ctx, s.db, box, pc.workspace.ID, forwardCredentials{
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
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.forward.set", pc.workspace.ID, details)
	}

	return &WorkspaceForwardConfigResponse{
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

// GetWorkspaceForwardCollectors lists available Forward collectors for the workspace.
//
//encore:api auth method=GET path=/api/users/:id/integrations/forward/collectors
func (s *Service) GetWorkspaceForwardCollectors(ctx context.Context, id string) (*WorkspaceForwardCollectorsResponse, error) {
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

	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil || forwardCfg == nil {
		return &WorkspaceForwardCollectorsResponse{Collectors: []WorkspaceForwardCollector{}}, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collectors").Err()
	}
	out := make([]WorkspaceForwardCollector, 0, len(collectors))
	for _, collector := range collectors {
		out = append(out, WorkspaceForwardCollector{
			ID:       strings.TrimSpace(collector.ID),
			Name:     strings.TrimSpace(collector.Name),
			Username: strings.TrimSpace(collector.Username),
		})
	}
	return &WorkspaceForwardCollectorsResponse{Collectors: out}, nil
}

// CreateWorkspaceForwardCollector creates a Forward collector for the workspace.
//
//encore:api auth method=POST path=/api/users/:id/integrations/forward/collectors
func (s *Service) CreateWorkspaceForwardCollector(ctx context.Context, id string) (*WorkspaceForwardCollectorCreateResponse, error) {
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

	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil || forwardCfg == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("Forward credentials required").Err()
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	name := strings.TrimSpace(pc.workspace.Slug)
	if name == "" {
		name = strings.TrimSpace(pc.workspace.ID)
	}
	collector, err := forwardCreateCollector(ctx, client, name)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
	}
	return &WorkspaceForwardCollectorCreateResponse{
		ID:               strings.TrimSpace(collector.ID),
		Name:             strings.TrimSpace(collector.Name),
		Username:         strings.TrimSpace(collector.Username),
		AuthorizationKey: strings.TrimSpace(collector.AuthorizationKey),
	}, nil
}

// DeleteWorkspaceForwardConfig removes Forward Networks credentials for a workspace.
//
//encore:api auth method=DELETE path=/api/users/:id/integrations/forward
func (s *Service) DeleteWorkspaceForwardConfig(ctx context.Context, id string) (*WorkspaceForwardConfigResponse, error) {
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
	if err := deleteWorkspaceForwardCredentials(ctx, s.db, pc.workspace.ID); err != nil {
		log.Printf("forward delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.forward.clear", pc.workspace.ID, "")
	}
	return &WorkspaceForwardConfigResponse{
		Configured: false,
		BaseURL:    defaultForwardBaseURL,
	}, nil
}
