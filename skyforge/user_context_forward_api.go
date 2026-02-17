package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"encore.dev/beta/errs"
)

type UserContextForwardConfigResponse struct {
	Configured  bool   `json:"configured"`
	BaseURL     string `json:"baseUrl"`
	Username    string `json:"username,omitempty"`
	CollectorID string `json:"collectorId,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	HasJumpKey  bool   `json:"hasJumpPrivateKey"`
	HasJumpCert bool   `json:"hasJumpCert"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

type UserContextForwardConfigRequest struct {
	BaseURL           string `json:"baseUrl"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	CollectorID       string `json:"collectorId"`
	CollectorUsername string `json:"collectorUsername"`
	JumpPrivateKey    string `json:"jumpPrivateKey"`
	JumpCert          string `json:"jumpCert"`
}

type UserContextForwardCollector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type UserContextForwardCollectorsResponse struct {
	Collectors []UserContextForwardCollector `json:"collectors"`
}

type UserContextForwardCollectorCreateResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthorizationKey string `json:"authorizationKey"`
}

type ApplyUserContextForwardCredentialSetRequest struct {
	CredentialID string `json:"credentialId"`
}

const defaultForwardBaseURL = "https://fwd.app"

// GetUserContextForwardConfig returns Forward Networks credentials for a user context.
//
//encore:api auth method=GET path=/api/user-contexts/:id/integrations/forward
func (s *Service) GetUserContextForwardConfig(ctx context.Context, id string) (*UserContextForwardConfigResponse, error) {
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
	rec, err := getUserContextForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userContext.ID)
	if err != nil {
		log.Printf("forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
	}
	if rec == nil {
		return &UserContextForwardConfigResponse{
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
	return &UserContextForwardConfigResponse{
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

// PutUserContextForwardConfig stores Forward Networks credentials for a user context.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/integrations/forward
func (s *Service) PutUserContextForwardConfig(ctx context.Context, id string, req *UserContextForwardConfigRequest) (*UserContextForwardConfigResponse, error) {
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
	current, err := getUserContextForwardCredentials(ctx, s.db, box, pc.userContext.ID)
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

	if err := putUserContextForwardCredentials(ctx, s.db, box, pc.userContext.ID, forwardCredentials{
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
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-context.forward.set", pc.userContext.ID, details)
	}

	return &UserContextForwardConfigResponse{
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

// GetUserContextForwardCollectors lists available Forward collectors for the user context.
//
//encore:api auth method=GET path=/api/user-contexts/:id/integrations/forward/collectors
func (s *Service) GetUserContextForwardCollectors(ctx context.Context, id string) (*UserContextForwardCollectorsResponse, error) {
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

	forwardCfg, err := s.forwardConfigForUserContext(ctx, pc.userContext.ID)
	if err != nil || forwardCfg == nil {
		return &UserContextForwardCollectorsResponse{Collectors: []UserContextForwardCollector{}}, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collectors").Err()
	}
	out := make([]UserContextForwardCollector, 0, len(collectors))
	for _, collector := range collectors {
		out = append(out, UserContextForwardCollector{
			ID:       strings.TrimSpace(collector.ID),
			Name:     strings.TrimSpace(collector.Name),
			Username: strings.TrimSpace(collector.Username),
		})
	}
	return &UserContextForwardCollectorsResponse{Collectors: out}, nil
}

// CreateUserContextForwardCollector creates a Forward collector for the user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/integrations/forward/collectors
func (s *Service) CreateUserContextForwardCollector(ctx context.Context, id string) (*UserContextForwardCollectorCreateResponse, error) {
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

	forwardCfg, err := s.forwardConfigForUserContext(ctx, pc.userContext.ID)
	if err != nil || forwardCfg == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("Forward credentials required").Err()
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	name := strings.TrimSpace(pc.userContext.Slug)
	if name == "" {
		name = strings.TrimSpace(pc.userContext.ID)
	}
	collector, err := forwardCreateCollector(ctx, client, name)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
	}
	return &UserContextForwardCollectorCreateResponse{
		ID:               strings.TrimSpace(collector.ID),
		Name:             strings.TrimSpace(collector.Name),
		Username:         strings.TrimSpace(collector.Username),
		AuthorizationKey: strings.TrimSpace(collector.AuthorizationKey),
	}, nil
}

// PostUserContextForwardConfig stores Forward Networks credentials for a user context (POST fallback).
//
//encore:api auth method=POST path=/api/user-contexts/:id/integrations/forward
func (s *Service) PostUserContextForwardConfig(ctx context.Context, id string, req *UserContextForwardConfigRequest) (*UserContextForwardConfigResponse, error) {
	return s.PutUserContextForwardConfig(ctx, id, req)
}

// DeleteUserContextForwardConfig removes Forward Networks credentials for a user context.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/integrations/forward
func (s *Service) DeleteUserContextForwardConfig(ctx context.Context, id string) (*UserContextForwardConfigResponse, error) {
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
	if err := deleteUserContextForwardCredentials(ctx, s.db, pc.userContext.ID); err != nil {
		log.Printf("forward delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-context.forward.clear", pc.userContext.ID, "")
	}
	return &UserContextForwardConfigResponse{
		Configured: false,
		BaseURL:    defaultForwardBaseURL,
	}, nil
}

// ApplyUserContextForwardCredentialSet copies a user-owned Forward credential set into the user-context
// Forward integration configuration (so the user context can use it for Forward-backed features).
//
// This uses "copy" semantics: future changes to the user credential set do not affect the user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/integrations/forward/apply-credential-set
func (s *Service) ApplyUserContextForwardCredentialSet(ctx context.Context, id string, req *ApplyUserContextForwardCredentialSetRequest) (*UserContextForwardConfigResponse, error) {
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
	if req == nil || strings.TrimSpace(req.CredentialID) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("credentialId is required").Err()
	}
	credID := strings.TrimSpace(req.CredentialID)

	box := newSecretBox(s.cfg.SessionSecret)
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctxReq, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}
	defer func() { _ = tx.Rollback() }()

	// Load source ciphertext row (user-scoped).
	var (
		srcName          string
		srcBase          sql.NullString
		srcSkipTLS       sql.NullBool
		srcUser          sql.NullString
		srcPass          sql.NullString
		srcCollectorID   sql.NullString
		srcCollectorUser sql.NullString
		srcAuthKey       sql.NullString
		srcDeviceUser    sql.NullString
		srcDevicePass    sql.NullString
		srcJumpHost      sql.NullString
		srcJumpUser      sql.NullString
		srcJumpKey       sql.NullString
		srcJumpCert      sql.NullString
	)
	err = tx.QueryRowContext(ctxReq, `
SELECT name,
       COALESCE(base_url_enc,''), COALESCE(skip_tls_verify,false),
       COALESCE(forward_username_enc,''), COALESCE(forward_password_enc,''),
       COALESCE(collector_id_enc,''), COALESCE(collector_username_enc,''), COALESCE(authorization_key_enc,''),
       COALESCE(device_username_enc,''), COALESCE(device_password_enc,''),
       COALESCE(jump_host_enc,''), COALESCE(jump_username_enc,''), COALESCE(jump_private_key_enc,''), COALESCE(jump_cert_enc,'')
  FROM sf_credentials
 WHERE id=$1 AND provider='forward' AND owner_username=$2 AND workspace_id IS NULL
`, credID, user.Username).Scan(
		&srcName,
		&srcBase, &srcSkipTLS,
		&srcUser, &srcPass,
		&srcCollectorID, &srcCollectorUser, &srcAuthKey,
		&srcDeviceUser, &srcDevicePass,
		&srcJumpHost, &srcJumpUser, &srcJumpKey, &srcJumpCert,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("credential set not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load credential set").Err()
	}

	// Ensure source has username/password.
	{
		u, _ := decryptNullStringOrEmpty(box, srcUser)
		p, _ := decryptNullStringOrEmpty(box, srcPass)
		if strings.TrimSpace(u) == "" || strings.TrimSpace(p) == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("credential set is missing username/password").Err()
		}
	}

	// Destination: reuse existing user-context credential id if present.
	var destID sql.NullString
	_ = tx.QueryRowContext(ctxReq, `SELECT COALESCE(credential_id,'') FROM sf_workspace_forward_credentials WHERE workspace_id=$1`, pc.userContext.ID).Scan(&destID)
	workspaceCredID := strings.TrimSpace(destID.String)
	if workspaceCredID == "" {
		workspaceCredID = uuid.NewString()
	}

	name := "user-context forward"
	if strings.TrimSpace(srcName) != "" {
		name = fmt.Sprintf("user-context forward (from %s)", strings.TrimSpace(srcName))
	}

	// Upsert user-context credential row by copying ciphertext directly.
	_, err = tx.ExecContext(ctxReq, `
INSERT INTO sf_credentials (
  id, owner_username, workspace_id, provider, name,
  base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
  collector_id_enc, collector_username_enc, authorization_key_enc,
  device_username_enc, device_password_enc,
  jump_host_enc, jump_username_enc, jump_private_key_enc, jump_cert_enc,
  created_at, updated_at
) VALUES (
  $1, NULL, $2, 'forward', $3,
  NULLIF($4,''), $5, NULLIF($6,''), NULLIF($7,''),
  NULLIF($8,''), NULLIF($9,''), NULLIF($10,''),
  NULLIF($11,''), NULLIF($12,''),
  NULLIF($13,''), NULLIF($14,''), NULLIF($15,''), NULLIF($16,''),
  now(), now()
)
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  base_url_enc=excluded.base_url_enc,
  skip_tls_verify=excluded.skip_tls_verify,
  forward_username_enc=excluded.forward_username_enc,
  forward_password_enc=excluded.forward_password_enc,
  collector_id_enc=excluded.collector_id_enc,
  collector_username_enc=excluded.collector_username_enc,
  authorization_key_enc=excluded.authorization_key_enc,
  device_username_enc=excluded.device_username_enc,
  device_password_enc=excluded.device_password_enc,
  jump_host_enc=excluded.jump_host_enc,
  jump_username_enc=excluded.jump_username_enc,
  jump_private_key_enc=excluded.jump_private_key_enc,
  jump_cert_enc=excluded.jump_cert_enc,
  updated_at=now()
`, workspaceCredID, pc.userContext.ID, name,
		strings.TrimSpace(srcBase.String),
		(srcSkipTLS.Valid && srcSkipTLS.Bool),
		strings.TrimSpace(srcUser.String),
		strings.TrimSpace(srcPass.String),
		strings.TrimSpace(srcCollectorID.String),
		strings.TrimSpace(srcCollectorUser.String),
		strings.TrimSpace(srcAuthKey.String),
		strings.TrimSpace(srcDeviceUser.String),
		strings.TrimSpace(srcDevicePass.String),
		strings.TrimSpace(srcJumpHost.String),
		strings.TrimSpace(srcJumpUser.String),
		strings.TrimSpace(srcJumpKey.String),
		strings.TrimSpace(srcJumpCert.String),
	)
	if err != nil {
		log.Printf("user-context forward apply credential set: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}

	_, err = tx.ExecContext(ctxReq, `
INSERT INTO sf_workspace_forward_credentials (
  workspace_id, credential_id,
  base_url, username, password,
  collector_id, collector_username,
  device_username, device_password,
  jump_host, jump_username, jump_private_key, jump_cert,
  updated_at
) VALUES ($1,$2,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,now())
ON CONFLICT (workspace_id) DO UPDATE SET
  credential_id=excluded.credential_id,
  updated_at=now()
`, pc.userContext.ID, workspaceCredID)
	if err != nil {
		log.Printf("user-context forward apply credential set link: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}

	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}

	// Return current config (best-effort).
	return s.GetUserContextForwardConfig(ctx, id)
}
