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

type UserForwardConfigResponse struct {
	Configured  bool   `json:"configured"`
	BaseURL     string `json:"baseUrl"`
	Username    string `json:"username,omitempty"`
	CollectorID string `json:"collectorId,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	HasJumpKey  bool   `json:"hasJumpPrivateKey"`
	HasJumpCert bool   `json:"hasJumpCert"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

type UserForwardConfigRequest struct {
	BaseURL           string `json:"baseUrl"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	CollectorID       string `json:"collectorId"`
	CollectorUsername string `json:"collectorUsername"`
	JumpPrivateKey    string `json:"jumpPrivateKey"`
	JumpCert          string `json:"jumpCert"`
}

type UserForwardCollector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type UserForwardCollectorsResponse struct {
	Collectors []UserForwardCollector `json:"collectors"`
}

type UserForwardCollectorCreateResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthorizationKey string `json:"authorizationKey"`
}

type ApplyUserForwardCredentialSetRequest struct {
	CredentialID string `json:"credentialId"`
}

const defaultForwardBaseURL = "https://fwd.app"

// GetUserForwardConfig returns Forward Networks credentials for a scope.
func (s *Service) GetUserForwardConfig(ctx context.Context, id string) (*UserForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	rec, err := getOwnerForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.context.ID)
	if err != nil {
		log.Printf("forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
	}
	if rec == nil {
		return &UserForwardConfigResponse{
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
	return &UserForwardConfigResponse{
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

// PutUserForwardConfig stores Forward Networks credentials for a scope.
func (s *Service) PutUserForwardConfig(ctx context.Context, id string, req *UserForwardConfigRequest) (*UserForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	current, err := getOwnerForwardCredentials(ctx, s.db, box, pc.context.ID)
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

	if err := putOwnerForwardCredentials(ctx, s.db, box, pc.context.ID, forwardCredentials{
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
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.forward.set", pc.context.ID, details)
	}

	return &UserForwardConfigResponse{
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

// GetUserForwardCollectors lists available Forward collectors for the scope.
func (s *Service) GetUserForwardCollectors(ctx context.Context, id string) (*UserForwardCollectorsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	forwardCfg, err := s.forwardConfigForOwner(ctx, pc.context.ID)
	if err != nil || forwardCfg == nil {
		return &UserForwardCollectorsResponse{Collectors: []UserForwardCollector{}}, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collectors").Err()
	}
	out := make([]UserForwardCollector, 0, len(collectors))
	for _, collector := range collectors {
		out = append(out, UserForwardCollector{
			ID:       strings.TrimSpace(collector.ID),
			Name:     strings.TrimSpace(collector.Name),
			Username: strings.TrimSpace(collector.Username),
		})
	}
	return &UserForwardCollectorsResponse{Collectors: out}, nil
}

// CreateUserForwardCollector creates a Forward collector for the scope.
func (s *Service) CreateUserForwardCollector(ctx context.Context, id string) (*UserForwardCollectorCreateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	forwardCfg, err := s.forwardConfigForOwner(ctx, pc.context.ID)
	if err != nil || forwardCfg == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("Forward credentials required").Err()
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	name := strings.TrimSpace(pc.context.Slug)
	if name == "" {
		name = strings.TrimSpace(pc.context.ID)
	}
	collector, err := forwardCreateCollector(ctx, client, name)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
	}
	return &UserForwardCollectorCreateResponse{
		ID:               strings.TrimSpace(collector.ID),
		Name:             strings.TrimSpace(collector.Name),
		Username:         strings.TrimSpace(collector.Username),
		AuthorizationKey: strings.TrimSpace(collector.AuthorizationKey),
	}, nil
}

// PostUserForwardConfig stores Forward Networks credentials for a scope (POST fallback).
func (s *Service) PostUserForwardConfig(ctx context.Context, id string, req *UserForwardConfigRequest) (*UserForwardConfigResponse, error) {
	return s.PutUserForwardConfig(ctx, id, req)
}

// DeleteUserForwardConfig removes Forward Networks credentials for a scope.
func (s *Service) DeleteUserForwardConfig(ctx context.Context, id string) (*UserForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := deleteOwnerForwardCredentials(ctx, s.db, pc.context.ID); err != nil {
		log.Printf("forward delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.forward.clear", pc.context.ID, "")
	}
	return &UserForwardConfigResponse{
		Configured: false,
		BaseURL:    defaultForwardBaseURL,
	}, nil
}

// ApplyUserForwardCredentialSet copies a user-owned Forward credential set into the scope-scoped
// Forward integration configuration (so the scope can use it for Forward-backed features).
//
// This uses "copy" semantics: future changes to the user credential set do not affect the scope.
func (s *Service) ApplyUserForwardCredentialSet(ctx context.Context, id string, req *ApplyUserForwardCredentialSetRequest) (*UserForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
 WHERE id=$1 AND provider='forward' AND owner_username=$2 AND owner_username IS NULL
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

	// Destination: reuse existing scope credential id if present.
	var destID sql.NullString
	_ = tx.QueryRowContext(ctxReq, `SELECT COALESCE(credential_id,'') FROM sf_owner_forward_credentials WHERE owner_username=$1`, pc.context.ID).Scan(&destID)
	scopeCredID := strings.TrimSpace(destID.String)
	if scopeCredID == "" {
		scopeCredID = uuid.NewString()
	}

	name := "context forward"
	if strings.TrimSpace(srcName) != "" {
		name = fmt.Sprintf("context forward (from %s)", strings.TrimSpace(srcName))
	}

	// Upsert scope-scoped credential row by copying ciphertext directly.
	_, err = tx.ExecContext(ctxReq, `
INSERT INTO sf_credentials (
  id, owner_username, owner_username, provider, name,
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
`, scopeCredID, pc.context.ID, name,
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
		log.Printf("context forward apply credential set: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}

	_, err = tx.ExecContext(ctxReq, `
INSERT INTO sf_owner_forward_credentials (
  owner_username, credential_id,
  base_url, username, password,
  collector_id, collector_username,
  device_username, device_password,
  jump_host, jump_username, jump_private_key, jump_cert,
  updated_at
) VALUES ($1,$2,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,now())
ON CONFLICT (owner_username) DO UPDATE SET
  credential_id=excluded.credential_id,
  updated_at=now()
`, pc.context.ID, scopeCredID)
	if err != nil {
		log.Printf("context forward apply credential set link: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}

	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to apply credential set").Err()
	}

	// Return current config (best-effort).
	return s.GetUserForwardConfig(ctx, id)
}
