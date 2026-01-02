package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ProjectForwardConfigResponse struct {
	Configured  bool   `json:"configured"`
	BaseURL     string `json:"baseUrl"`
	Username    string `json:"username,omitempty"`
	CollectorID string `json:"collectorId,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

type ProjectForwardConfigRequest struct {
	BaseURL           string `json:"baseUrl"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	CollectorID       string `json:"collectorId"`
	CollectorUsername string `json:"collectorUsername"`
}

type ProjectForwardCollector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type ProjectForwardCollectorsResponse struct {
	Collectors []ProjectForwardCollector `json:"collectors"`
}

type ProjectForwardCollectorCreateResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthorizationKey string `json:"authorizationKey"`
}

const defaultForwardBaseURL = "https://fwd.app"

// GetProjectForwardConfig returns Forward Networks credentials for a workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/integrations/forward
func (s *Service) GetProjectForwardConfig(ctx context.Context, id string) (*ProjectForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	rec, err := getProjectForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.project.ID)
	if err != nil {
		log.Printf("forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
	}
	if rec == nil {
		return &ProjectForwardConfigResponse{
			Configured:  false,
			BaseURL:     defaultForwardBaseURL,
			HasPassword: false,
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
	return &ProjectForwardConfigResponse{
		Configured:  baseURL != "" && rec.Username != "" && rec.Password != "",
		BaseURL:     baseURL,
		Username:    rec.Username,
		CollectorID: rec.CollectorID,
		HasPassword: rec.Password != "",
		UpdatedAt:   updatedAt,
	}, nil
}

// PutProjectForwardConfig stores Forward Networks credentials for a workspace.
//
//encore:api auth method=PUT path=/api/workspaces/:id/integrations/forward
func (s *Service) PutProjectForwardConfig(ctx context.Context, id string, req *ProjectForwardConfigRequest) (*ProjectForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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

	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current, err := getProjectForwardCredentials(ctx, s.db, box, pc.project.ID)
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

	if err := putProjectForwardCredentials(ctx, s.db, box, pc.project.ID, forwardCredentials{
		BaseURL:       baseURL,
		Username:      username,
		Password:      password,
		CollectorID:   collectorID,
		CollectorUser: collectorUser,
	}); err != nil {
		log.Printf("forward put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store Forward config").Err()
	}

	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("baseUrl=%s username=%s", baseURL, username)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.forward.set", pc.project.ID, details)
	}

	return &ProjectForwardConfigResponse{
		Configured:  true,
		BaseURL:     baseURL,
		Username:    username,
		CollectorID: collectorID,
		HasPassword: true,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetProjectForwardCollectors lists available Forward collectors for the workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/integrations/forward/collectors
func (s *Service) GetProjectForwardCollectors(ctx context.Context, id string) (*ProjectForwardCollectorsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	forwardCfg, err := s.forwardConfigForProject(ctx, pc.project.ID)
	if err != nil || forwardCfg == nil {
		return &ProjectForwardCollectorsResponse{Collectors: []ProjectForwardCollector{}}, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collectors").Err()
	}
	out := make([]ProjectForwardCollector, 0, len(collectors))
	for _, collector := range collectors {
		out = append(out, ProjectForwardCollector{
			ID:       strings.TrimSpace(collector.ID),
			Name:     strings.TrimSpace(collector.Name),
			Username: strings.TrimSpace(collector.Username),
		})
	}
	return &ProjectForwardCollectorsResponse{Collectors: out}, nil
}

// CreateProjectForwardCollector creates a Forward collector for the workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/integrations/forward/collectors
func (s *Service) CreateProjectForwardCollector(ctx context.Context, id string) (*ProjectForwardCollectorCreateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	forwardCfg, err := s.forwardConfigForProject(ctx, pc.project.ID)
	if err != nil || forwardCfg == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("Forward credentials required").Err()
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	name := strings.TrimSpace(pc.project.Slug)
	if name == "" {
		name = strings.TrimSpace(pc.project.ID)
	}
	collector, err := forwardCreateCollector(ctx, client, name)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
	}
	return &ProjectForwardCollectorCreateResponse{
		ID:               strings.TrimSpace(collector.ID),
		Name:             strings.TrimSpace(collector.Name),
		Username:         strings.TrimSpace(collector.Username),
		AuthorizationKey: strings.TrimSpace(collector.AuthorizationKey),
	}, nil
}

// PostProjectForwardConfig stores Forward Networks credentials for a workspace (POST fallback).
//
//encore:api auth method=POST path=/api/workspaces/:id/integrations/forward
func (s *Service) PostProjectForwardConfig(ctx context.Context, id string, req *ProjectForwardConfigRequest) (*ProjectForwardConfigResponse, error) {
	return s.PutProjectForwardConfig(ctx, id, req)
}

// DeleteProjectForwardConfig removes Forward Networks credentials for a workspace.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/integrations/forward
func (s *Service) DeleteProjectForwardConfig(ctx context.Context, id string) (*ProjectForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := deleteProjectForwardCredentials(ctx, s.db, pc.project.ID); err != nil {
		log.Printf("forward delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.forward.clear", pc.project.ID, "")
	}
	return &ProjectForwardConfigResponse{
		Configured: false,
		BaseURL:    defaultForwardBaseURL,
	}, nil
}
