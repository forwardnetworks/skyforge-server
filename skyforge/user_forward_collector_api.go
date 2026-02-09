package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"github.com/google/uuid"
)

type UserForwardCollectorResponse struct {
	Configured        bool                    `json:"configured"`
	BaseURL           string                  `json:"baseUrl"`
	SkipTLSVerify     bool                    `json:"skipTlsVerify"`
	Username          string                  `json:"username,omitempty"`
	CollectorID       string                  `json:"collectorId,omitempty"`
	CollectorUsername string                  `json:"collectorUsername,omitempty"`
	AuthorizationKey  string                  `json:"authorizationKey,omitempty"`
	Runtime           *collectorRuntimeStatus `json:"runtime,omitempty"`
	ForwardCollector  *ForwardCollectorInfo   `json:"forwardCollector,omitempty"`
	HasPassword       bool                    `json:"hasPassword"`
	HasJumpKey        bool                    `json:"hasJumpPrivateKey"`
	HasJumpCert       bool                    `json:"hasJumpCert"`
	UpdatedAt         string                  `json:"updatedAt,omitempty"`
}

type ForwardCollectorInfo struct {
	ID              string   `json:"id,omitempty"`
	Name            string   `json:"name,omitempty"`
	Username        string   `json:"username,omitempty"`
	Status          string   `json:"status,omitempty"`
	Connected       *bool    `json:"connected,omitempty"`
	ConnectedAt     string   `json:"connectedAt,omitempty"`
	LastConnectedAt string   `json:"lastConnectedAt,omitempty"`
	LastSeenAt      string   `json:"lastSeenAt,omitempty"`
	UpdatedAt       string   `json:"updatedAt,omitempty"`
	Version         string   `json:"version,omitempty"`
	UpdateStatus    string   `json:"updateStatus,omitempty"`
	ExternalIP      string   `json:"externalIp,omitempty"`
	InternalIPs     []string `json:"internalIps,omitempty"`
}

type PutUserForwardCollectorRequest struct {
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

func defaultCollectorNameForUser(username string) string {
	username = strings.TrimSpace(strings.ToLower(username))
	username = strings.ReplaceAll(username, "@", "-")
	username = strings.ReplaceAll(username, ".", "-")
	username = strings.ReplaceAll(username, " ", "-")
	username = strings.ReplaceAll(username, "_", "-")
	username = strings.ReplaceAll(username, "/", "-")
	username = strings.ReplaceAll(username, ":", "-")
	username = strings.Trim(username, "-")
	if username == "" {
		username = "user"
	}
	if len(username) > 48 {
		username = username[:48]
	}
	return "skyforge-" + username
}

// GetUserForwardCollector returns the authenticated user's Forward collector settings.
//
//encore:api auth method=GET path=/api/forward/collector
func (s *Service) GetUserForwardCollector(ctx context.Context) (*UserForwardCollectorResponse, error) {
	if !s.cfg.Features.ForwardEnabled {
		return nil, errs.B().Code(errs.NotFound).Msg("Forward integration is disabled").Err()
	}
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := listUserForwardCollectorConfigRows(ctxReq, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	var sel *userForwardCollectorConfigRow
	for i := range rows {
		if rows[i].IsDefault {
			sel = &rows[i]
			break
		}
	}
	if sel == nil && len(rows) > 0 {
		sel = &rows[0]
	}
	if sel == nil {
		return &UserForwardCollectorResponse{
			Configured:    false,
			BaseURL:       defaultForwardBaseURL,
			SkipTLSVerify: false,
			Runtime:       nil,
			HasPassword:   false,
			HasJumpKey:    false,
			HasJumpCert:   false,
		}, nil
	}

	baseURL := strings.TrimSpace(sel.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	updatedAt := ""
	if !sel.UpdatedAt.IsZero() {
		updatedAt = sel.UpdatedAt.UTC().Format(time.RFC3339)
	}

	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel2 := context.WithTimeout(ctxReq, 2*time.Second)
		defer cancel2()
		if st, err := getCollectorRuntimeStatusByName(ctx2, collectorDeploymentNameForConfig(user.Username, sel.ID, sel.IsDefault)); err == nil {
			runtime = st
		}
	}

	var fwdCollector *ForwardCollectorInfo
	{
		ctx2, cancel2 := context.WithTimeout(ctxReq, 5*time.Second)
		defer cancel2()
		if strings.TrimSpace(sel.ForwardUsername) != "" && strings.TrimSpace(sel.ForwardPassword) != "" && strings.TrimSpace(sel.CollectorID) != "" {
			client, err := newForwardClient(forwardCredentials{
				BaseURL:       baseURL,
				SkipTLSVerify: sel.SkipTLSVerify,
				Username:      sel.ForwardUsername,
				Password:      sel.ForwardPassword,
			})
			if err == nil {
				if collectors, err := forwardListCollectors(ctx2, client); err == nil {
					for i := range collectors {
						if strings.EqualFold(strings.TrimSpace(collectors[i].ID), strings.TrimSpace(sel.CollectorID)) {
							match := collectors[i]
							info := &ForwardCollectorInfo{
								ID:           strings.TrimSpace(match.ID),
								Name:         strings.TrimSpace(match.Name),
								Username:     strings.TrimSpace(match.Username),
								Version:      strings.TrimSpace(match.Version),
								UpdateStatus: strings.TrimSpace(match.UpdateStatus),
								ExternalIP:   strings.TrimSpace(match.ExternalIP),
								InternalIPs:  match.InternalIPs,
							}
							status := strings.TrimSpace(match.ConnectionStatus)
							if status == "" {
								status = strings.TrimSpace(match.Status)
							}
							if status != "" {
								info.Status = status
							}
							if strings.EqualFold(status, "CONNECTED") {
								yes := true
								info.Connected = &yes
							} else if status != "" {
								no := false
								info.Connected = &no
							}
							if info.ID != "" || info.Name != "" || info.Username != "" || info.Status != "" || info.Connected != nil {
								fwdCollector = info
							}
							break
						}
					}
				}
			}
		}
	}

	return &UserForwardCollectorResponse{
		Configured:        baseURL != "" && strings.TrimSpace(sel.ForwardUsername) != "" && strings.TrimSpace(sel.ForwardPassword) != "",
		BaseURL:           baseURL,
		SkipTLSVerify:     sel.SkipTLSVerify,
		Username:          strings.TrimSpace(sel.ForwardUsername),
		CollectorID:       strings.TrimSpace(sel.CollectorID),
		CollectorUsername: strings.TrimSpace(sel.CollectorUsername),
		AuthorizationKey:  strings.TrimSpace(sel.AuthorizationKey),
		Runtime:           runtime,
		ForwardCollector:  fwdCollector,
		HasPassword:       strings.TrimSpace(sel.ForwardPassword) != "",
		HasJumpKey:        false,
		HasJumpCert:       false,
		UpdatedAt:         updatedAt,
	}, nil
}

// PutUserForwardCollector stores Forward credentials and ensures a per-user collector exists.
//
//encore:api auth method=PUT path=/api/forward/collector
func (s *Service) PutUserForwardCollector(ctx context.Context, req *PutUserForwardCollectorRequest) (*UserForwardCollectorResponse, error) {
	if !s.cfg.Features.ForwardEnabled {
		return nil, errs.B().Code(errs.NotFound).Msg("Forward integration is disabled").Err()
	}
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
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
	skipTLSVerify := req.SkipTLSVerify
	forwardUser := strings.TrimSpace(req.Username)
	forwardPass := strings.TrimSpace(req.Password)

	if forwardUser == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	// Forward collector provisioning can be slow (multiple API calls + possible TLS/network latency).
	// Keep a generous timeout so the UI doesn't get flaky 503s under mild load.
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	rows, err := listUserForwardCollectorConfigRows(ctx, s.db, box, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to load Forward collector settings: %v", err)).Err()
	}
	var current *userForwardCollectorConfigRow
	for i := range rows {
		if rows[i].IsDefault {
			current = &rows[i]
			break
		}
	}
	if current == nil && len(rows) > 0 {
		current = &rows[0]
	}
	if forwardPass == "" && current != nil {
		forwardPass = strings.TrimSpace(current.ForwardPassword)
	}
	if forwardPass == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("password is required").Err()
	}

	cfg := forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      forwardUser,
		Password:      forwardPass,
	}
	client, err := newForwardClient(cfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		// Treat 401/403 as auth errors, but keep other failures as transient to avoid
		// confusing users when Forward is temporarily unreachable.
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden") {
			log.Printf("forward auth check failed (%s): %v", user.Username, err)
			return nil, errs.B().Code(errs.Unauthenticated).Msg("Forward authentication failed").Err()
		}
		log.Printf("forward list collectors (auth check %s): %v", user.Username, err)
		return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to reach Forward: %v", err)).Err()
	}

	collectorID := ""
	collectorUsername := ""
	authKey := ""
	if current != nil {
		collectorID = strings.TrimSpace(current.CollectorID)
		collectorUsername = strings.TrimSpace(current.CollectorUsername)
		authKey = strings.TrimSpace(current.AuthorizationKey)
	}
	name := defaultCollectorNameForUser(user.Username)
	if collectorID == "" || collectorUsername == "" || authKey == "" {
		for _, existing := range collectors {
			if strings.EqualFold(strings.TrimSpace(existing.Name), name) {
				// Best-effort delete so create can succeed and returns a fresh auth key.
				delID := strings.TrimSpace(existing.ID)
				if delID == "" {
					delID = strings.TrimSpace(existing.Name)
				}
				if err := forwardDeleteCollector(ctx, client, delID); err != nil {
					log.Printf("forward delete existing collector (%s): %v", existing.Name, err)
				}
				break
			}
		}
		collector, err := forwardCreateCollector(ctx, client, name)
		if err != nil {
			log.Printf("forward create collector (%s): %v", name, err)
			// Handle common race/compat case: collector already exists but the list
			// response didn't include it (or returned an unexpected shape).
			if strings.Contains(strings.ToLower(err.Error()), "already exists") {
				if err := forwardDeleteCollector(ctx, client, name); err != nil {
					log.Printf("forward delete existing collector (fallback %s): %v", name, err)
				}
				if collector2, err2 := forwardCreateCollector(ctx, client, name); err2 == nil {
					collector = collector2
					err = nil
				} else {
					log.Printf("forward create collector retry (%s): %v", name, err2)
					return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to create Forward collector: %v", err2)).Err()
				}
			} else {
				// Include the Forward error text so users can self-diagnose common failures
				// (RBAC, licensing, etc.) without requiring server log access.
				return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to create Forward collector: %v", err)).Err()
			}
		}
		collectorID = strings.TrimSpace(collector.ID)
		collectorUsername = strings.TrimSpace(collector.Username)
		authKey = strings.TrimSpace(collector.AuthorizationKey)
	}

	// Persist into the unified tables: sf_credentials + sf_user_forward_collectors.
	ctxSave, cancelSave := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSave()
	tx, err := s.db.BeginTx(ctxSave, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	defer func() { _ = tx.Rollback() }()

	configID := ""
	configName := ""
	credID := ""
	if current != nil {
		configID = strings.TrimSpace(current.ID)
		configName = strings.TrimSpace(current.Name)
		credID = strings.TrimSpace(current.CredentialID)
	}
	if configName == "" {
		configName = "Default"
	}
	if configID == "" {
		// Create (or reuse) a user collector config named "Default".
		var existingID sql.NullString
		_ = tx.QueryRowContext(ctxSave, `SELECT id FROM sf_user_forward_collectors WHERE username=$1 AND lower(name)=lower($2) ORDER BY updated_at DESC LIMIT 1`, user.Username, configName).Scan(&existingID)
		if strings.TrimSpace(existingID.String) != "" {
			configID = strings.TrimSpace(existingID.String)
		} else {
			configID = uuid.NewString()
		}
	}
	if credID == "" {
		credID = uuid.NewString()
	}

	// Ensure only one default collector config.
	if _, err := tx.ExecContext(ctxSave, `UPDATE sf_user_forward_collectors SET is_default=false WHERE username=$1`, user.Username); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	if _, err := tx.ExecContext(ctxSave, `INSERT INTO sf_user_forward_collectors (
  id, username, name,
  credential_id,
  base_url, skip_tls_verify, forward_username, forward_password,
  collector_id, collector_username, authorization_key,
  created_at, updated_at, is_default
) VALUES ($1,$2,$3,$4,NULL,$5,NULL,NULL,NULL,NULL,NULL,now(),now(),true)
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  credential_id=excluded.credential_id,
  skip_tls_verify=excluded.skip_tls_verify,
  updated_at=now(),
  is_default=true
`, configID, user.Username, configName, credID, skipTLSVerify); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}

	// Preserve existing user settings JSON blobs when setting default collector.
	cur, _ := getUserSettings(ctxSave, s.db, user.Username)
	defaultEnv := "[]"
	extRepos := "[]"
	if cur != nil {
		if strings.TrimSpace(cur.DefaultEnvJSON) != "" {
			defaultEnv = cur.DefaultEnvJSON
		}
		if strings.TrimSpace(cur.ExternalTemplateReposJSON) != "" {
			extRepos = cur.ExternalTemplateReposJSON
		}
	}
	if _, err := tx.ExecContext(ctxSave, `
INSERT INTO sf_user_settings (user_id, default_forward_collector_config_id, default_env_json, external_template_repos_json)
VALUES ($1,$2,$3,$4)
ON CONFLICT(user_id) DO UPDATE SET
  default_forward_collector_config_id=excluded.default_forward_collector_config_id,
  default_env_json=excluded.default_env_json,
  external_template_repos_json=excluded.external_template_repos_json,
  updated_at=now()
`, user.Username, configID, defaultEnv, extRepos); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}

	if err := upsertUserForwardCredentialSetWithCollector(ctxSave, tx, box, credID, user.Username, "Collector: "+configName, forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      forwardUser,
		Password:      forwardPass,
	}, collectorID, collectorUsername, authKey); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}

	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}

	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		deployName := collectorDeploymentNameForConfig(user.Username, configID, true)
		if st, err := ensureCollectorDeployedForName(ctx2, s.cfg, user.Username, deployName, authKey, baseURL, skipTLSVerify); err != nil {
			log.Printf("collector deploy failed: %v", err)
		} else {
			runtime = st
		}
	}

	return &UserForwardCollectorResponse{
		Configured:        true,
		BaseURL:           baseURL,
		SkipTLSVerify:     skipTLSVerify,
		Username:          forwardUser,
		CollectorID:       collectorID,
		CollectorUsername: collectorUsername,
		AuthorizationKey:  authKey,
		Runtime:           runtime,
		HasPassword:       true,
		HasJumpKey:        false,
		HasJumpCert:       false,
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ResetUserForwardCollector rotates the user's Forward collector by creating a new one and storing its authorization key.
//
// NOTE: This does not delete any existing collector in Forward; it only updates the Skyforge profile.
//
//encore:api auth method=POST path=/api/forward/collector/reset
func (s *Service) ResetUserForwardCollector(ctx context.Context) (*UserForwardCollectorResponse, error) {
	if !s.cfg.Features.ForwardEnabled {
		return nil, errs.B().Code(errs.NotFound).Msg("Forward integration is disabled").Err()
	}
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := listUserForwardCollectorConfigRows(ctx, s.db, box, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	var current *userForwardCollectorConfigRow
	for i := range rows {
		if rows[i].IsDefault {
			current = &rows[i]
			break
		}
	}
	if current == nil && len(rows) > 0 {
		current = &rows[0]
	}
	if current == nil || strings.TrimSpace(current.ForwardUsername) == "" || strings.TrimSpace(current.ForwardPassword) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials required").Err()
	}
	baseURL := strings.TrimSpace(current.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	forwardUser := strings.TrimSpace(current.ForwardUsername)
	forwardPass := strings.TrimSpace(current.ForwardPassword)
	skipTLSVerify := current.SkipTLSVerify
	configID := strings.TrimSpace(current.ID)
	configName := strings.TrimSpace(current.Name)
	credID := strings.TrimSpace(current.CredentialID)
	if configName == "" {
		configName = "Default"
	}
	if configID == "" {
		configID = uuid.NewString()
	}
	if credID == "" {
		credID = uuid.NewString()
	}
	client, err := newForwardClient(forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      forwardUser,
		Password:      forwardPass,
	})
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}

	name := defaultCollectorNameForUser(user.Username)
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list Forward collectors").Err()
	}
	for _, existing := range collectors {
		if strings.EqualFold(strings.TrimSpace(existing.Name), name) {
			if err := forwardDeleteCollector(ctx, client, strings.TrimSpace(existing.Name)); err != nil {
				log.Printf("forward delete existing collector (%s): %v", existing.Name, err)
			}
			break
		}
	}
	collector, err := forwardCreateCollector(ctx, client, name)
	if err != nil {
		log.Printf("forward create collector (%s): %v", name, err)
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			if err := forwardDeleteCollector(ctx, client, name); err != nil {
				log.Printf("forward delete existing collector (reset fallback %s): %v", name, err)
			}
			collector2, err2 := forwardCreateCollector(ctx, client, name)
			if err2 != nil {
				log.Printf("forward create collector retry (%s): %v", name, err2)
				return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to create Forward collector: %v", err2)).Err()
			}
			collector = collector2
		} else {
			return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to create Forward collector: %v", err)).Err()
		}
	}

	collectorID := strings.TrimSpace(collector.ID)
	collectorUsername := strings.TrimSpace(collector.Username)
	authKey := strings.TrimSpace(collector.AuthorizationKey)

	// Persist rotated auth key into the unified tables.
	ctxSave, cancelSave := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSave()
	tx, err := s.db.BeginTx(ctxSave, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctxSave, `UPDATE sf_user_forward_collectors SET is_default=false WHERE username=$1`, user.Username); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	if _, err := tx.ExecContext(ctxSave, `INSERT INTO sf_user_forward_collectors (
  id, username, name,
  credential_id,
  base_url, skip_tls_verify, forward_username, forward_password,
  collector_id, collector_username, authorization_key,
  created_at, updated_at, is_default
) VALUES ($1,$2,$3,$4,NULL,$5,NULL,NULL,NULL,NULL,NULL,now(),now(),true)
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  credential_id=excluded.credential_id,
  skip_tls_verify=excluded.skip_tls_verify,
  updated_at=now(),
  is_default=true
`, configID, user.Username, configName, credID, skipTLSVerify); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	// Preserve existing user settings JSON blobs.
	cur, _ := getUserSettings(ctxSave, s.db, user.Username)
	defaultEnv := "[]"
	extRepos := "[]"
	if cur != nil {
		if strings.TrimSpace(cur.DefaultEnvJSON) != "" {
			defaultEnv = cur.DefaultEnvJSON
		}
		if strings.TrimSpace(cur.ExternalTemplateReposJSON) != "" {
			extRepos = cur.ExternalTemplateReposJSON
		}
	}
	if _, err := tx.ExecContext(ctxSave, `
INSERT INTO sf_user_settings (user_id, default_forward_collector_config_id, default_env_json, external_template_repos_json)
VALUES ($1,$2,$3,$4)
ON CONFLICT(user_id) DO UPDATE SET
  default_forward_collector_config_id=excluded.default_forward_collector_config_id,
  default_env_json=excluded.default_env_json,
  external_template_repos_json=excluded.external_template_repos_json,
  updated_at=now()
`, user.Username, configID, defaultEnv, extRepos); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	if err := upsertUserForwardCredentialSetWithCollector(ctxSave, tx, box, credID, user.Username, "Collector: "+configName, forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      forwardUser,
		Password:      forwardPass,
	}, collectorID, collectorUsername, authKey); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save Forward settings").Err()
	}

	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if strings.TrimSpace(configID) != "" {
			deployName := collectorDeploymentNameForConfig(user.Username, configID, true)
			if st, err := ensureCollectorDeployedForName(ctx2, s.cfg, user.Username, deployName, authKey, baseURL, skipTLSVerify); err != nil {
				log.Printf("collector deploy failed: %v", err)
			} else {
				runtime = st
			}
		} else if st, err := ensureCollectorDeployed(ctx2, s.cfg, user.Username, authKey, baseURL, skipTLSVerify); err != nil {
			log.Printf("collector deploy failed: %v", err)
		} else {
			runtime = st
		}
	}

	return &UserForwardCollectorResponse{
		Configured:        true,
		BaseURL:           baseURL,
		SkipTLSVerify:     skipTLSVerify,
		Username:          forwardUser,
		CollectorID:       collectorID,
		CollectorUsername: collectorUsername,
		AuthorizationKey:  authKey,
		Runtime:           runtime,
		HasPassword:       true,
		HasJumpKey:        false,
		HasJumpCert:       false,
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type UserCollectorRuntimeResponse struct {
	Runtime *collectorRuntimeStatus `json:"runtime,omitempty"`
}

type UserCollectorLogsParams struct {
	Tail int `query:"tail" encore:"optional"`
}

type UserCollectorLogsResponse struct {
	PodName string `json:"podName,omitempty"`
	Logs    string `json:"logs,omitempty"`
}

type RestartUserCollectorResponse struct {
	Runtime *collectorRuntimeStatus `json:"runtime,omitempty"`
}

// RestartUserCollector triggers a rolling restart of the user's in-cluster collector Deployment.
// This is used to pull down a newer image when using `:latest`.
//
//encore:api auth method=POST path=/api/forward/collector/restart
func (s *Service) RestartUserCollector(ctx context.Context) (*RestartUserCollectorResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := restartCollectorDeployment(ctx2, user.Username); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg(err.Error()).Err()
	}
	ctx3, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	st, _ := getCollectorRuntimeStatus(ctx3, user.Username)
	return &RestartUserCollectorResponse{Runtime: st}, nil
}

// GetUserCollectorRuntime returns the in-cluster runtime status for the user's collector.
//
//encore:api auth method=GET path=/api/forward/collector/runtime
func (s *Service) GetUserCollectorRuntime(ctx context.Context) (*UserCollectorRuntimeResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := getCollectorRuntimeStatus(ctx, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector runtime").Err()
	}
	return &UserCollectorRuntimeResponse{Runtime: st}, nil
}

// GetUserCollectorLogs returns recent log lines from the user's in-cluster collector pod.
//
//encore:api auth method=GET path=/api/forward/collector/logs
func (s *Service) GetUserCollectorLogs(ctx context.Context, params *UserCollectorLogsParams) (*UserCollectorLogsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	tail := 200
	if params != nil && params.Tail > 0 {
		if params.Tail > 2000 {
			tail = 2000
		} else {
			tail = params.Tail
		}
	}

	ctxSt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := getCollectorRuntimeStatus(ctxSt, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector runtime").Err()
	}
	if st == nil || strings.TrimSpace(st.PodName) == "" {
		return &UserCollectorLogsResponse{}, nil
	}

	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	logs, err := getCollectorClientdLog(ctxReq, st.Namespace, st.PodName, tail)
	if err != nil {
		// Fall back to container stdout logs for clusters that disallow exec or images
		// that don't write clientd logs into /scratch.
		log.Printf("collector clientd logs failed: %v", err)
		logs2, err2 := getCollectorPodLogs(ctxReq, st.Namespace, st.PodName, "collector", tail)
		if err2 != nil {
			log.Printf("collector pod logs failed: %v", err2)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector logs").Err()
		}
		logs = logs2
	}
	return &UserCollectorLogsResponse{PodName: st.PodName, Logs: logs}, nil
}

// ClearUserForwardCollector deletes the stored user Forward collector settings.
//
//encore:api auth method=DELETE path=/api/forward/collector
func (s *Service) ClearUserForwardCollector(ctx context.Context) (*UserForwardCollectorResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := listUserForwardCollectorConfigRows(ctxReq, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("user forward clear list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear Forward collector settings").Err()
	}

	// Delete configs + their referenced credential sets.
	tx, err := s.db.BeginTx(ctxReq, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear Forward collector settings").Err()
	}
	defer func() { _ = tx.Rollback() }()

	credIDs := make([]string, 0, len(rows))
	for _, r := range rows {
		if id := strings.TrimSpace(r.CredentialID); id != "" {
			credIDs = append(credIDs, id)
		}
	}

	if _, err := tx.ExecContext(ctxReq, `DELETE FROM sf_user_forward_collectors WHERE username=$1`, user.Username); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear Forward collector settings").Err()
	}
	if _, err := tx.ExecContext(ctxReq, `UPDATE sf_user_settings SET default_forward_collector_config_id=NULL WHERE user_id=$1`, user.Username); err != nil && !isMissingDBRelation(err) {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear Forward collector settings").Err()
	}
	if len(credIDs) > 0 {
		// Best-effort: delete only the credential sets referenced by collector configs.
		for _, id := range credIDs {
			_, _ = tx.ExecContext(ctxReq, `DELETE FROM sf_credentials WHERE id=$1 AND provider='forward' AND owner_username=$2 AND workspace_id IS NULL`, strings.TrimSpace(id), user.Username)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear Forward collector settings").Err()
	}

	// Best-effort: delete in-cluster collector resources for each config.
	go func(username string, rows []userForwardCollectorConfigRow) {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel2()
		for _, r := range rows {
			deployName := collectorDeploymentNameForConfig(username, r.ID, r.IsDefault)
			if err := deleteCollectorResourcesByName(ctx2, deployName); err != nil {
				log.Printf("collector delete resources (%s): %v", deployName, err)
			}
		}
	}(user.Username, rows)

	return &UserForwardCollectorResponse{
		Configured:  false,
		BaseURL:     defaultForwardBaseURL,
		Runtime:     nil,
		HasPassword: false,
	}, nil
}
