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

// GetUserForwardCollector returns the authenticated user's Forward collector settings.
//
//encore:api auth method=GET path=/api/forward/collector
func (s *Service) GetUserForwardCollector(ctx context.Context) (*UserForwardCollectorResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	if rec == nil {
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
	if !rec.UpdatedAt.IsZero() {
		updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	baseURL := strings.TrimSpace(rec.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if st, err := getCollectorRuntimeStatus(ctx2, user.Username); err == nil {
			runtime = st
		}
	}
	var fwdCollector *ForwardCollectorInfo
	{
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		box := newSecretBox(s.cfg.SessionSecret)
		creds, err := getUserForwardCredentials(ctx2, s.db, box, user.Username)
		if err == nil && creds != nil && strings.TrimSpace(creds.BaseURL) != "" && strings.TrimSpace(creds.ForwardUsername) != "" && strings.TrimSpace(creds.ForwardPassword) != "" && strings.TrimSpace(creds.CollectorID) != "" {
			client, err := newForwardClient(forwardCredentials{
				BaseURL:       creds.BaseURL,
				SkipTLSVerify: creds.SkipTLSVerify,
				Username:      creds.ForwardUsername,
				Password:      creds.ForwardPassword,
			})
			if err == nil {
				if collectors, err := forwardListCollectors(ctx2, client); err == nil {
					var match *forwardCollector
					for i := range collectors {
						if strings.EqualFold(strings.TrimSpace(collectors[i].ID), strings.TrimSpace(creds.CollectorID)) {
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
		Configured:        baseURL != "" && rec.ForwardUsername != "" && rec.ForwardPassword != "",
		BaseURL:           baseURL,
		SkipTLSVerify:     rec.SkipTLSVerify,
		Username:          rec.ForwardUsername,
		CollectorID:       rec.CollectorID,
		CollectorUsername: rec.CollectorUsername,
		AuthorizationKey:  rec.AuthorizationKey,
		Runtime:           runtime,
		ForwardCollector:  fwdCollector,
		HasPassword:       rec.ForwardPassword != "",
		HasJumpKey:        false,
		HasJumpCert:       false,
		UpdatedAt:         updatedAt,
	}, nil
}

// PutUserForwardCollector stores Forward credentials and ensures a per-user collector exists.
//
//encore:api auth method=PUT path=/api/forward/collector
func (s *Service) PutUserForwardCollector(ctx context.Context, req *PutUserForwardCollectorRequest) (*UserForwardCollectorResponse, error) {
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

	current, err := getUserForwardCredentials(ctx, s.db, box, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	if forwardPass == "" && current != nil {
		forwardPass = current.ForwardPassword
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
	if _, err := forwardListCollectors(ctx, client); err != nil {
		log.Printf("forward auth check failed (%s): %v", user.Username, err)
		return nil, errs.B().Code(errs.Unauthenticated).Msg("Forward authentication failed").Err()
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
		collectors, err := forwardListCollectors(ctx, client)
		if err != nil {
			log.Printf("forward list collectors (%s): %v", user.Username, err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to list Forward collectors").Err()
		}
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

	if err := putUserForwardCredentials(ctx, s.db, box, user.Username, userForwardCredentials{
		BaseURL:           baseURL,
		SkipTLSVerify:     skipTLSVerify,
		ForwardUsername:   forwardUser,
		ForwardPassword:   forwardPass,
		CollectorID:       collectorID,
		CollectorUsername: collectorUsername,
		AuthorizationKey:  authKey,
	}); err != nil {
		log.Printf("user forward put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store Forward collector settings").Err()
	}

	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if st, err := ensureCollectorDeployed(ctx2, s.cfg, user.Username, authKey, baseURL, skipTLSVerify); err != nil {
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
	current, err := getUserForwardCredentials(ctx, s.db, box, user.Username)
	if err != nil {
		log.Printf("user forward get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward collector settings").Err()
	}
	if current == nil || strings.TrimSpace(current.ForwardUsername) == "" || strings.TrimSpace(current.ForwardPassword) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials required").Err()
	}
	client, err := newForwardClient(forwardCredentials{
		BaseURL:       current.BaseURL,
		SkipTLSVerify: current.SkipTLSVerify,
		Username:      current.ForwardUsername,
		Password:      current.ForwardPassword,
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

	current.CollectorID = strings.TrimSpace(collector.ID)
	current.CollectorUsername = strings.TrimSpace(collector.Username)
	current.AuthorizationKey = strings.TrimSpace(collector.AuthorizationKey)
	if err := putUserForwardCredentials(ctx, s.db, box, user.Username, *current); err != nil {
		log.Printf("user forward put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store Forward collector settings").Err()
	}

	var runtime *collectorRuntimeStatus
	{
		ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if st, err := ensureCollectorDeployed(ctx2, s.cfg, user.Username, current.AuthorizationKey, strings.TrimSpace(current.BaseURL), current.SkipTLSVerify); err != nil {
			log.Printf("collector deploy failed: %v", err)
		} else {
			runtime = st
		}
	}

	return &UserForwardCollectorResponse{
		Configured:        true,
		BaseURL:           strings.TrimSpace(current.BaseURL),
		SkipTLSVerify:     current.SkipTLSVerify,
		Username:          strings.TrimSpace(current.ForwardUsername),
		CollectorID:       strings.TrimSpace(current.CollectorID),
		CollectorUsername: strings.TrimSpace(current.CollectorUsername),
		AuthorizationKey:  strings.TrimSpace(current.AuthorizationKey),
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
	logs, err := getCollectorPodLogs(ctxReq, st.Namespace, st.PodName, "collector", tail)
	if err != nil {
		log.Printf("collector logs failed: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector logs").Err()
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
