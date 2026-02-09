package skyforge

import (
	"context"
	"database/sql"
	"errors"
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

type userForwardCredentials struct {
	BaseURL           string
	SkipTLSVerify     bool
	ForwardUsername   string
	ForwardPassword   string
	CollectorID       string
	CollectorUsername string
	AuthorizationKey  string
	UpdatedAt         time.Time
}

func getUserForwardCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userForwardCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var baseURL, forwardUser, forwardPass sql.NullString
	var collectorID, collectorUser, authKey sql.NullString
	var skipTLSVerify sql.NullBool
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT base_url, forward_username, forward_password,
  COALESCE(collector_id, ''), COALESCE(collector_username, ''), COALESCE(authorization_key, ''),
  COALESCE(skip_tls_verify, false),
  updated_at
FROM sf_user_forward_credentials WHERE username=$1`, username).Scan(
		&baseURL,
		&forwardUser,
		&forwardPass,
		&collectorID,
		&collectorUser,
		&authKey,
		&skipTLSVerify,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if isMissingDBRelation(err) {
			return nil, nil
		}
		if isMissingDBColumn(err, "skip_tls_verify") {
			// Backward-compat: older clusters might not have the skip_tls_verify column yet.
			skipTLSVerify = sql.NullBool{Valid: true, Bool: false}
			err2 := db.QueryRowContext(ctx, `SELECT base_url, forward_username, forward_password,
  COALESCE(collector_id, ''), COALESCE(collector_username, ''), COALESCE(authorization_key, ''),
  updated_at
FROM sf_user_forward_credentials WHERE username=$1`, username).Scan(
				&baseURL,
				&forwardUser,
				&forwardPass,
				&collectorID,
				&collectorUser,
				&authKey,
				&updatedAt,
			)
			if err2 != nil {
				if errors.Is(err2, sql.ErrNoRows) || isMissingDBRelation(err2) {
					return nil, nil
				}
				return nil, err2
			}
			err = nil
		} else {
			return nil, err
		}
	}
	baseURLValue, err := box.decrypt(baseURL.String)
	if err != nil {
		log.Printf("user forward decrypt base_url (%s): %v", username, err)
		return nil, nil
	}
	forwardUserValue, err := box.decrypt(forwardUser.String)
	if err != nil {
		log.Printf("user forward decrypt forward_username (%s): %v", username, err)
		return nil, nil
	}
	forwardPassValue, err := box.decrypt(forwardPass.String)
	if err != nil {
		log.Printf("user forward decrypt forward_password (%s): %v", username, err)
		return nil, nil
	}
	collectorIDValue, err := box.decrypt(collectorID.String)
	if err != nil {
		log.Printf("user forward decrypt collector_id (%s): %v", username, err)
		return nil, nil
	}
	collectorUserValue, err := box.decrypt(collectorUser.String)
	if err != nil {
		log.Printf("user forward decrypt collector_username (%s): %v", username, err)
		return nil, nil
	}
	authKeyValue, err := box.decrypt(authKey.String)
	if err != nil {
		log.Printf("user forward decrypt authorization_key (%s): %v", username, err)
		return nil, nil
	}

	rec := &userForwardCredentials{
		BaseURL:           strings.TrimSpace(baseURLValue),
		SkipTLSVerify:     skipTLSVerify.Valid && skipTLSVerify.Bool,
		ForwardUsername:   strings.TrimSpace(forwardUserValue),
		ForwardPassword:   strings.TrimSpace(forwardPassValue),
		CollectorID:       strings.TrimSpace(collectorIDValue),
		CollectorUsername: strings.TrimSpace(collectorUserValue),
		AuthorizationKey:  strings.TrimSpace(authKeyValue),
	}
	if rec.CollectorUsername == "" && rec.AuthorizationKey != "" {
		// Backward-compat / resiliency: some collectors only persist the auth key
		// which encodes the collector username as "<username>:<token>".
		if before, _, ok := strings.Cut(rec.AuthorizationKey, ":"); ok {
			rec.CollectorUsername = strings.TrimSpace(before)
		}
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putUserForwardCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string, rec userForwardCredentials) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	baseURL := strings.TrimSpace(rec.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	forwardUser := strings.TrimSpace(rec.ForwardUsername)
	forwardPass := strings.TrimSpace(rec.ForwardPassword)
	if forwardUser == "" || forwardPass == "" {
		return fmt.Errorf("username and password are required")
	}
	if strings.TrimSpace(rec.CollectorUsername) == "" && strings.TrimSpace(rec.AuthorizationKey) != "" {
		if before, _, ok := strings.Cut(rec.AuthorizationKey, ":"); ok {
			rec.CollectorUsername = strings.TrimSpace(before)
		}
	}
	encBaseURL, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return err
	}
	encFwdUser, err := encryptIfPlain(box, forwardUser)
	if err != nil {
		return err
	}
	encFwdPass, err := encryptIfPlain(box, forwardPass)
	if err != nil {
		return err
	}
	encCollectorID, err := encryptIfPlain(box, rec.CollectorID)
	if err != nil {
		return err
	}
	encCollectorUser, err := encryptIfPlain(box, rec.CollectorUsername)
	if err != nil {
		return err
	}
	encAuthKey, err := encryptIfPlain(box, rec.AuthorizationKey)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_forward_credentials (
  username, base_url, forward_username, forward_password,
  skip_tls_verify,
  collector_id, collector_username, authorization_key,
  updated_at
) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),now())
ON CONFLICT (username) DO UPDATE SET
  base_url=excluded.base_url,
  forward_username=excluded.forward_username,
  forward_password=excluded.forward_password,
  skip_tls_verify=excluded.skip_tls_verify,
  collector_id=excluded.collector_id,
  collector_username=excluded.collector_username,
  authorization_key=excluded.authorization_key,
  updated_at=now()`,
		username,
		encBaseURL,
		encFwdUser,
		encFwdPass,
		rec.SkipTLSVerify,
		encCollectorID,
		encCollectorUser,
		encAuthKey,
	)
	if isMissingDBRelation(err) {
		return fmt.Errorf("forward credentials store not initialized")
	}
	if isMissingDBColumn(err, "skip_tls_verify") {
		_, err2 := db.ExecContext(ctx, `INSERT INTO sf_user_forward_credentials (
  username, base_url, forward_username, forward_password,
  collector_id, collector_username, authorization_key,
  updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),now())
ON CONFLICT (username) DO UPDATE SET
  base_url=excluded.base_url,
  forward_username=excluded.forward_username,
  forward_password=excluded.forward_password,
  collector_id=excluded.collector_id,
  collector_username=excluded.collector_username,
  authorization_key=excluded.authorization_key,
  updated_at=now()`,
			username,
			encBaseURL,
			encFwdUser,
			encFwdPass,
			encCollectorID,
			encCollectorUser,
			encAuthKey,
		)
		if isMissingDBRelation(err2) {
			return fmt.Errorf("forward credentials store not initialized")
		}
		return err2
	}
	return err
}

func deleteUserForwardCredentials(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_forward_credentials WHERE username=$1`, username)
	if isMissingDBRelation(err) {
		return nil
	}
	return err
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

type legacyForwardCollectorResolved struct {
	ConfigID   string
	ConfigName string
	IsDefault  bool
	UpdatedAt  time.Time

	CredentialID string
	Set          *forwardCredentialSet

	Legacy *userForwardCredentials
}

func (s *Service) resolveLegacyForwardCollectorConfig(ctx context.Context, username string) (*legacyForwardCollectorResolved, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, nil
	}

	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cfgID, _ := preferredUserForwardCollectorConfigID(ctxReq, s.db, username)
	cfgID = strings.TrimSpace(cfgID)

	// If the user has no default configured, try a friendly fallback by name.
	if cfgID == "" {
		_ = s.db.QueryRowContext(ctxReq, `SELECT id FROM sf_user_forward_collectors WHERE username=$1 AND lower(name)=lower('Default') ORDER BY updated_at DESC LIMIT 1`, username).Scan(&cfgID)
		cfgID = strings.TrimSpace(cfgID)
	}

	if cfgID != "" {
		var name string
		var isDefault bool
		var credID string
		var updatedAt time.Time
		err := s.db.QueryRowContext(ctxReq, `SELECT name, COALESCE(is_default,false), COALESCE(credential_id,''), updated_at
FROM sf_user_forward_collectors
WHERE username=$1 AND id=$2`, username, cfgID).Scan(&name, &isDefault, &credID, &updatedAt)
		if err == nil {
			out := &legacyForwardCollectorResolved{
				ConfigID:     cfgID,
				ConfigName:   strings.TrimSpace(name),
				IsDefault:    isDefault,
				UpdatedAt:    updatedAt,
				CredentialID: strings.TrimSpace(credID),
			}
			if out.CredentialID != "" {
				box := newSecretBox(s.cfg.SessionSecret)
				set, err := getUserForwardCredentialSet(ctxReq, s.db, box, username, out.CredentialID)
				if err == nil && set != nil {
					out.Set = set
				}
			}
			// If we found a usable credential set, prefer it and don't touch legacy.
			if out.Set != nil && strings.TrimSpace(out.Set.Username) != "" && strings.TrimSpace(out.Set.Password) != "" {
				return out, nil
			}
		}
	}

	// Backward-compat: legacy single-collector table.
	box := newSecretBox(s.cfg.SessionSecret)
	legacy, err := getUserForwardCredentials(ctxReq, s.db, box, username)
	if err != nil {
		return nil, err
	}
	if legacy == nil {
		return nil, nil
	}
	return &legacyForwardCollectorResolved{Legacy: legacy}, nil
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

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolved, err := s.resolveLegacyForwardCollectorConfig(ctx, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	if resolved == nil || (resolved.Set == nil && resolved.Legacy == nil) {
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
	updatedAt := ""
	baseURL := defaultForwardBaseURL
	skipTLSVerify := false
	forwardUser := ""
	forwardPass := ""
	collectorID := ""
	collectorUsername := ""
	authKey := ""
	if resolved.Set != nil {
		baseURL = strings.TrimSpace(resolved.Set.BaseURL)
		if baseURL == "" {
			baseURL = defaultForwardBaseURL
		}
		skipTLSVerify = resolved.Set.SkipTLSVerify
		forwardUser = strings.TrimSpace(resolved.Set.Username)
		forwardPass = strings.TrimSpace(resolved.Set.Password)
		collectorID = strings.TrimSpace(resolved.Set.CollectorID)
		collectorUsername = strings.TrimSpace(resolved.Set.CollectorUsername)
		authKey = strings.TrimSpace(resolved.Set.AuthorizationKey)
		if !resolved.UpdatedAt.IsZero() {
			updatedAt = resolved.UpdatedAt.UTC().Format(time.RFC3339)
		}
	} else if resolved.Legacy != nil {
		rec := resolved.Legacy
		baseURL = strings.TrimSpace(rec.BaseURL)
		if baseURL == "" {
			baseURL = defaultForwardBaseURL
		}
		skipTLSVerify = rec.SkipTLSVerify
		forwardUser = strings.TrimSpace(rec.ForwardUsername)
		forwardPass = strings.TrimSpace(rec.ForwardPassword)
		collectorID = strings.TrimSpace(rec.CollectorID)
		collectorUsername = strings.TrimSpace(rec.CollectorUsername)
		authKey = strings.TrimSpace(rec.AuthorizationKey)
		if !rec.UpdatedAt.IsZero() {
			updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}

	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if resolved != nil && strings.TrimSpace(resolved.ConfigID) != "" {
			if st, err := getCollectorRuntimeStatusByName(ctx2, collectorDeploymentNameForConfig(user.Username, resolved.ConfigID, resolved.IsDefault)); err == nil {
				runtime = st
			}
		} else if st, err := getCollectorRuntimeStatus(ctx2, user.Username); err == nil {
			runtime = st
		}
	}
	var fwdCollector *ForwardCollectorInfo
	{
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if strings.TrimSpace(baseURL) != "" && strings.TrimSpace(forwardUser) != "" && strings.TrimSpace(forwardPass) != "" && strings.TrimSpace(collectorID) != "" {
			client, err := newForwardClient(forwardCredentials{
				BaseURL:       baseURL,
				SkipTLSVerify: skipTLSVerify,
				Username:      forwardUser,
				Password:      forwardPass,
			})
			if err == nil {
				if collectors, err := forwardListCollectors(ctx2, client); err == nil {
					var match *forwardCollector
					for i := range collectors {
						if strings.EqualFold(strings.TrimSpace(collectors[i].ID), strings.TrimSpace(collectorID)) {
							match = &collectors[i]
							break
						}
					}
					if match != nil {
						info := &ForwardCollectorInfo{
							ID:           strings.TrimSpace(match.ID),
							Name:         strings.TrimSpace(match.Name),
							Username:     strings.TrimSpace(match.Username),
							Version:      strings.TrimSpace(match.Version),
							UpdateStatus: strings.TrimSpace(match.UpdateStatus),
							ExternalIP:   strings.TrimSpace(match.ExternalIP),
							InternalIPs:  match.InternalIPs,
						}
						// Prefer the newer `connectionStatus` field.
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
					}
				}
			}
		}
	}
	return &UserForwardCollectorResponse{
		Configured:        baseURL != "" && forwardUser != "" && forwardPass != "",
		BaseURL:           baseURL,
		SkipTLSVerify:     skipTLSVerify,
		Username:          forwardUser,
		CollectorID:       collectorID,
		CollectorUsername: collectorUsername,
		AuthorizationKey:  authKey,
		Runtime:           runtime,
		ForwardCollector:  fwdCollector,
		HasPassword:       forwardPass != "",
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

	currentResolved, err := s.resolveLegacyForwardCollectorConfig(ctx, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("failed to load Forward collector settings: %v", err)).Err()
	}
	if forwardPass == "" && currentResolved != nil {
		if currentResolved.Set != nil {
			forwardPass = strings.TrimSpace(currentResolved.Set.Password)
		} else if currentResolved.Legacy != nil {
			forwardPass = strings.TrimSpace(currentResolved.Legacy.ForwardPassword)
		}
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
	if currentResolved != nil {
		if currentResolved.Set != nil {
			collectorID = strings.TrimSpace(currentResolved.Set.CollectorID)
			collectorUsername = strings.TrimSpace(currentResolved.Set.CollectorUsername)
			authKey = strings.TrimSpace(currentResolved.Set.AuthorizationKey)
		} else if currentResolved.Legacy != nil {
			collectorID = strings.TrimSpace(currentResolved.Legacy.CollectorID)
			collectorUsername = strings.TrimSpace(currentResolved.Legacy.CollectorUsername)
			authKey = strings.TrimSpace(currentResolved.Legacy.AuthorizationKey)
		}
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
	if currentResolved != nil {
		configID = strings.TrimSpace(currentResolved.ConfigID)
		configName = strings.TrimSpace(currentResolved.ConfigName)
		credID = strings.TrimSpace(currentResolved.CredentialID)
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
	currentResolved, err := s.resolveLegacyForwardCollectorConfig(ctx, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	var baseURL, forwardUser, forwardPass string
	var skipTLSVerify bool
	var configID string
	var credID string
	if currentResolved != nil && currentResolved.Set != nil {
		baseURL = strings.TrimSpace(currentResolved.Set.BaseURL)
		forwardUser = strings.TrimSpace(currentResolved.Set.Username)
		forwardPass = strings.TrimSpace(currentResolved.Set.Password)
		skipTLSVerify = currentResolved.Set.SkipTLSVerify
		configID = strings.TrimSpace(currentResolved.ConfigID)
		credID = strings.TrimSpace(currentResolved.CredentialID)
	} else if currentResolved != nil && currentResolved.Legacy != nil {
		baseURL = strings.TrimSpace(currentResolved.Legacy.BaseURL)
		forwardUser = strings.TrimSpace(currentResolved.Legacy.ForwardUsername)
		forwardPass = strings.TrimSpace(currentResolved.Legacy.ForwardPassword)
		skipTLSVerify = currentResolved.Legacy.SkipTLSVerify
	}
	if forwardUser == "" || forwardPass == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials required").Err()
	}
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
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

	configName := "Default"
	if currentResolved != nil && strings.TrimSpace(currentResolved.ConfigName) != "" {
		configName = strings.TrimSpace(currentResolved.ConfigName)
	}
	if configID == "" {
		configID = uuid.NewString()
	}
	if credID == "" {
		credID = uuid.NewString()
	}
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
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserForwardCredentials(ctx, s.db, user.Username); err != nil {
		log.Printf("user forward delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear Forward collector settings").Err()
	}
	{
		ctx2, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := deleteCollectorResources(ctx2, user.Username); err != nil {
			log.Printf("collector delete failed: %v", err)
		}
	}
	return &UserForwardCollectorResponse{
		Configured:  false,
		BaseURL:     defaultForwardBaseURL,
		Runtime:     nil,
		HasPassword: false,
	}, nil
}
