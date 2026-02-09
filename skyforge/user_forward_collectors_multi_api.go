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

type UserForwardCollectorConfigSummary struct {
	ID                string                  `json:"id"`
	Name              string                  `json:"name"`
	BaseURL           string                  `json:"baseUrl"`
	SkipTLSVerify     bool                    `json:"skipTlsVerify"`
	Username          string                  `json:"username,omitempty"`
	CollectorID       string                  `json:"collectorId,omitempty"`
	CollectorUsername string                  `json:"collectorUsername,omitempty"`
	IsDefault         bool                    `json:"isDefault"`
	UpdatedAt         string                  `json:"updatedAt,omitempty"`
	Runtime           *collectorRuntimeStatus `json:"runtime,omitempty"`
	ForwardCollector  *ForwardCollectorInfo   `json:"forwardCollector,omitempty"`
	DecryptionFailed  bool                    `json:"decryptionFailed,omitempty"`
}

type ListUserForwardCollectorConfigsResponse struct {
	Collectors []UserForwardCollectorConfigSummary `json:"collectors"`
}

type CreateUserForwardCollectorConfigRequest struct {
	Name               string `json:"name"`
	BaseURL            string `json:"baseUrl"`
	SkipTLSVerify      bool   `json:"skipTlsVerify"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	SetDefault         bool   `json:"setDefault"`
	SourceCredentialID string `json:"sourceCredentialId,omitempty"`
}

type DeleteUserForwardCollectorConfigResponse struct {
	Deleted bool `json:"deleted"`
}

type userForwardCollectorConfigRow struct {
	ID                string
	Username          string
	Name              string
	CredentialID      string
	BaseURL           string
	SkipTLSVerify     bool
	ForwardUsername   string
	ForwardPassword   string
	CollectorID       string
	CollectorUsername string
	AuthorizationKey  string
	UpdatedAt         time.Time
	IsDefault         bool
}

func collectorDeploymentNameForConfig(username, configID string, isDefault bool) string {
	if isDefault {
		return collectorResourceNameForUser(username)
	}
	return collectorResourceNameForUserCollector(username, configID)
}

func listUserForwardCollectorConfigRows(ctx context.Context, db *sql.DB, box *secretBox, username string) ([]userForwardCollectorConfigRow, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	rows, err := db.QueryContext(ctx, `SELECT id, username, name,
  COALESCE(credential_id, ''),
  base_url, COALESCE(skip_tls_verify, false), forward_username, forward_password,
  COALESCE(collector_id, ''), COALESCE(collector_username, ''), COALESCE(authorization_key, ''),
  updated_at, COALESCE(is_default, false)
FROM sf_user_forward_collectors WHERE username=$1
ORDER BY is_default DESC, name ASC`, username)
	if err != nil {
		if isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	out := []userForwardCollectorConfigRow{}
	for rows.Next() {
		var id, uname, name string
		var credID sql.NullString
		var baseURL, fwdUser, fwdPass sql.NullString
		var collectorID, collectorUser, authKey sql.NullString
		var skipTLSVerify sql.NullBool
		var updatedAt sql.NullTime
		var isDefault sql.NullBool
		if err := rows.Scan(&id, &uname, &name, &credID, &baseURL, &skipTLSVerify, &fwdUser, &fwdPass, &collectorID, &collectorUser, &authKey, &updatedAt, &isDefault); err != nil {
			return nil, err
		}
		rec := userForwardCollectorConfigRow{
			ID:           strings.TrimSpace(id),
			Username:     strings.TrimSpace(uname),
			Name:         strings.TrimSpace(name),
			CredentialID: strings.TrimSpace(credID.String),
			IsDefault:    isDefault.Valid && isDefault.Bool,
		}
		rec.SkipTLSVerify = skipTLSVerify.Valid && skipTLSVerify.Bool
		if updatedAt.Valid {
			rec.UpdatedAt = updatedAt.Time
		}

		// Preferred: referenced credential set.
		if strings.TrimSpace(rec.CredentialID) != "" {
			if set, err := getUserForwardCredentialSet(ctx, db, box, username, rec.CredentialID); err == nil && set != nil {
				rec.BaseURL = strings.TrimSpace(set.BaseURL)
				rec.SkipTLSVerify = set.SkipTLSVerify
				rec.ForwardUsername = strings.TrimSpace(set.Username)
				rec.ForwardPassword = strings.TrimSpace(set.Password)
				rec.CollectorID = strings.TrimSpace(set.CollectorID)
				rec.CollectorUsername = strings.TrimSpace(set.CollectorUsername)
				rec.AuthorizationKey = strings.TrimSpace(set.AuthorizationKey)
			} else {
				// Leave record present, but clear sensitive fields.
				rec.BaseURL = ""
				rec.ForwardUsername = ""
				rec.ForwardPassword = ""
				rec.CollectorID = ""
				rec.CollectorUsername = ""
				rec.AuthorizationKey = ""
			}
			out = append(out, rec)
			continue
		}

		// Fallback: legacy inline columns (encrypted).
		decOrEmpty := func(v sql.NullString) (string, bool) {
			if strings.TrimSpace(v.String) == "" {
				return "", false
			}
			if box == nil {
				return "", true
			}
			plain, err := box.decrypt(v.String)
			if err != nil {
				return "", true
			}
			return strings.TrimSpace(plain), false
		}
		var failed bool
		if v, bad := decOrEmpty(baseURL); bad {
			failed = true
		} else {
			rec.BaseURL = v
		}
		if v, bad := decOrEmpty(fwdUser); bad {
			failed = true
		} else {
			rec.ForwardUsername = v
		}
		if v, bad := decOrEmpty(fwdPass); bad {
			failed = true
		} else {
			rec.ForwardPassword = v
		}
		if v, bad := decOrEmpty(collectorID); bad {
			failed = true
		} else {
			rec.CollectorID = v
		}
		if v, bad := decOrEmpty(collectorUser); bad {
			failed = true
		} else {
			rec.CollectorUsername = v
		}
		if v, bad := decOrEmpty(authKey); bad {
			failed = true
		} else {
			rec.AuthorizationKey = v
		}

		// Store decryption failure by clearing sensitive fields and leaving the record present.
		if failed {
			rec.BaseURL = ""
			rec.ForwardUsername = ""
			rec.ForwardPassword = ""
			rec.CollectorID = ""
			rec.CollectorUsername = ""
			rec.AuthorizationKey = ""
		}
		out = append(out, rec)
	}
	return out, nil
}

func migrateLegacyUserForwardCollectorIfNeeded(ctx context.Context, db *sql.DB, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_user_forward_collectors WHERE username=$1`, username).Scan(&count); err != nil {
		if isMissingDBRelation(err) {
			return nil
		}
		return err
	}
	if count > 0 {
		return nil
	}

	// Copy ciphertext from the legacy per-user table into the new per-collector table.
	var baseURL, fwdUser, fwdPass sql.NullString
	var collectorID, collectorUser, authKey sql.NullString
	var skipTLSVerify sql.NullBool
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT base_url, forward_username, forward_password,
  COALESCE(collector_id, ''), COALESCE(collector_username, ''), COALESCE(authorization_key, ''),
  COALESCE(skip_tls_verify, false),
  updated_at
FROM sf_user_forward_credentials WHERE username=$1`, username).Scan(&baseURL, &fwdUser, &fwdPass, &collectorID, &collectorUser, &authKey, &skipTLSVerify, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil
		}
		return err
	}

	id := uuid.NewString()
	credID := uuid.NewString()
	now := time.Now().UTC()
	createdAt := now
	if updatedAt.Valid {
		createdAt = updatedAt.Time
	}
	tx, txErr := db.BeginTx(ctx, nil)
	if txErr != nil {
		return txErr
	}
	defer func() { _ = tx.Rollback() }()

	// Copy ciphertext as-is (no decrypt/re-encrypt) into the shared credentials table.
	_, err = tx.ExecContext(ctx, `
INSERT INTO sf_credentials (
  id, owner_username, workspace_id, provider, name,
  base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
  collector_id_enc, collector_username_enc, authorization_key_enc,
  created_at, updated_at
) VALUES ($1,$2,NULL,'forward',$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),$11,$12)
ON CONFLICT (id) DO NOTHING
`, credID, username, "default",
		baseURL.String, (skipTLSVerify.Valid && skipTLSVerify.Bool), fwdUser.String, fwdPass.String,
		collectorID.String, collectorUser.String, authKey.String,
		createdAt, createdAt,
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO sf_user_forward_collectors (
  id, username, name,
  credential_id,
  base_url, skip_tls_verify, forward_username, forward_password,
  collector_id, collector_username, authorization_key,
  created_at, updated_at, is_default
) VALUES ($1,$2,$3,$4,NULL,$5,NULL,NULL,NULL,NULL,NULL,$6,$7,true)`,
		id, username, "default",
		credID,
		(skipTLSVerify.Valid && skipTLSVerify.Bool),
		createdAt, createdAt,
	)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil
		}
		return err
	}

	// Prevent "phantom re-creation" if a user later deletes all configured collectors:
	// ListUserForwardCollectorConfigs calls migrateLegacyUserForwardCollectorIfNeeded when no collector
	// configs exist. If we keep the legacy row around, a delete would appear to "succeed" but the next
	// list would immediately re-import it, making it look like the UI delete didn't work.
	//
	// The multi-collector endpoints are the source of truth going forward; delete the legacy row
	// best-effort (it's safe to ignore missing-table errors on fresh installs).
	if _, delErr := db.ExecContext(ctx, `DELETE FROM sf_user_forward_credentials WHERE username=$1`, username); delErr != nil {
		if !isMissingDBRelation(delErr) {
			log.Printf("user forward collectors migrate: failed to delete legacy row: %v", delErr)
		}
	}

	return nil
}

// ListUserForwardCollectorConfigs lists Forward collector configurations managed by Skyforge for the current user.
//
//encore:api auth method=GET path=/api/forward/collector-configs
func (s *Service) ListUserForwardCollectorConfigs(ctx context.Context) (*ListUserForwardCollectorConfigsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = migrateLegacyUserForwardCollectorIfNeeded(ctxReq, s.db, user.Username)
	rows, err := listUserForwardCollectorConfigRows(ctxReq, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("user forward collectors list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list Forward collectors").Err()
	}

	out := make([]UserForwardCollectorConfigSummary, 0, len(rows))
	for _, r := range rows {
		baseURL := strings.TrimSpace(r.BaseURL)
		if baseURL == "" {
			baseURL = defaultForwardBaseURL
		}
		updatedAt := ""
		if !r.UpdatedAt.IsZero() {
			updatedAt = r.UpdatedAt.UTC().Format(time.RFC3339)
		}
		cfg := UserForwardCollectorConfigSummary{
			ID:                r.ID,
			Name:              r.Name,
			BaseURL:           baseURL,
			SkipTLSVerify:     r.SkipTLSVerify,
			Username:          r.ForwardUsername,
			CollectorID:       r.CollectorID,
			CollectorUsername: r.CollectorUsername,
			IsDefault:         r.IsDefault,
			UpdatedAt:         updatedAt,
			DecryptionFailed:  strings.TrimSpace(r.ForwardUsername) == "" && strings.TrimSpace(r.ForwardPassword) == "" && strings.TrimSpace(r.CollectorID) == "" && strings.TrimSpace(r.AuthorizationKey) == "",
		}
		// Best-effort runtime and Forward status.
		{
			ctx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
			defer cancel2()
			if st, err := getCollectorRuntimeStatusByName(ctx2, collectorDeploymentNameForConfig(user.Username, r.ID, r.IsDefault)); err == nil {
				cfg.Runtime = st
			}
		}
		if strings.TrimSpace(r.ForwardUsername) != "" && strings.TrimSpace(r.ForwardPassword) != "" && strings.TrimSpace(r.CollectorID) != "" {
			ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
			defer cancel2()
			client, err := newForwardClient(forwardCredentials{
				BaseURL:       baseURL,
				SkipTLSVerify: r.SkipTLSVerify,
				Username:      r.ForwardUsername,
				Password:      r.ForwardPassword,
			})
			if err == nil {
				if collectors, err := forwardListCollectors(ctx2, client); err == nil {
					for i := range collectors {
						if strings.EqualFold(strings.TrimSpace(collectors[i].ID), strings.TrimSpace(r.CollectorID)) {
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
							cfg.ForwardCollector = info
							break
						}
					}
				}
			}
		}
		out = append(out, cfg)
	}
	return &ListUserForwardCollectorConfigsResponse{Collectors: out}, nil
}

// CreateUserForwardCollectorConfig creates a new Forward collector configuration and deploys a matching in-cluster collector.
//
//encore:api auth method=POST path=/api/forward/collector-configs
func (s *Service) CreateUserForwardCollectorConfig(ctx context.Context, req *CreateUserForwardCollectorConfigRequest) (*UserForwardCollectorConfigSummary, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	// Governance guardrails (admin-configurable).
	if policy, err := loadGovernancePolicy(ctx, s.db); err == nil {
		if err := enforceGovernanceCollectorCreate(ctx, s.db, user.Username, policy); err != nil {
			return nil, err
		}
	} else {
		log.Printf("governance policy load failed (ignored): %v", err)
	}

	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	skipTLSVerify := req.SkipTLSVerify
	fwdUser := strings.TrimSpace(req.Username)
	fwdPass := strings.TrimSpace(req.Password)

	// Optional: use a saved credential set as the source for Forward API auth.
	if srcID := strings.TrimSpace(req.SourceCredentialID); srcID != "" {
		box := newSecretBox(s.cfg.SessionSecret)
		ctxReq, cancelReq := context.WithTimeout(ctx, 5*time.Second)
		defer cancelReq()
		set, err := getUserForwardCredentialSet(ctxReq, s.db, box, user.Username, srcID)
		if err != nil {
			log.Printf("collector create: failed to load source credential set: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load credential set").Err()
		}
		if set == nil {
			return nil, errs.B().Code(errs.NotFound).Msg("credential set not found").Err()
		}
		if strings.TrimSpace(set.Username) == "" || strings.TrimSpace(set.Password) == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("credential set is missing username/password").Err()
		}
		// Prefer the set's base URL and TLS mode (request can still override baseURL if provided).
		if strings.TrimSpace(set.BaseURL) != "" {
			baseURL = strings.TrimSpace(set.BaseURL)
		}
		skipTLSVerify = set.SkipTLSVerify
		fwdUser = strings.TrimSpace(set.Username)
		fwdPass = strings.TrimSpace(set.Password)
	}

	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultForwardBaseURL
	}
	if fwdUser == "" || fwdPass == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username and password are required").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	// Keep request-scoped work bounded, but do NOT let a short timeout abort the
	// in-cluster collector deploy (PVC provision/pod pulls can legitimately take
	// a few minutes).
	ctxReq, cancelReq := context.WithTimeout(ctx, 90*time.Second)
	defer cancelReq()

	// Create a Forward-side collector (do not attempt to delete any existing collectors).
	client, err := newForwardClient(forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      fwdUser,
		Password:      fwdPass,
	})
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	// Basic auth check.
	if _, err := forwardListCollectors(ctxReq, client); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden") {
			return nil, errs.B().Code(errs.Unauthenticated).Msg("Forward authentication failed").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach Forward").Err()
	}

	configID := uuid.NewString()
	baseCollectorName := fmt.Sprintf("skyforge-%s", sanitizeKubeDNSLabelPart(user.Username, 48))
	shortID := strings.ReplaceAll(configID, "-", "")
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	isConflict := func(err error) bool {
		if err == nil {
			return false
		}
		msg := strings.ToLower(err.Error())
		// Forward typically returns HTTP 409 for "already exists", but we've observed
		// HTTP 400 with an "already exists" message in the payload.
		if strings.Contains(msg, "failed (409)") || strings.Contains(msg, "status 409") || (strings.Contains(msg, "409") && strings.Contains(msg, "already")) {
			return true
		}
		// Example:
		//   forward create collector failed (400): {"message":"Collector named ... already exists"}
		if strings.Contains(msg, "failed (400)") && strings.Contains(msg, "collector") && strings.Contains(msg, "already exists") {
			return true
		}
		return false
	}

	var (
		forwardCollectorName string
		created              *forwardCollectorCreateResponse
	)
	for attempt := 0; attempt < 3; attempt++ {
		switch attempt {
		case 0:
			forwardCollectorName = baseCollectorName
		case 1:
			forwardCollectorName = fmt.Sprintf("%s-%s", baseCollectorName, shortID)
		default:
			forwardCollectorName = fmt.Sprintf("%s-%s-%s", baseCollectorName, shortID, uuid.NewString()[:4])
		}
		created, err = forwardCreateCollector(ctxReq, client, forwardCollectorName)
		if err == nil {
			break
		}
		if !isConflict(err) {
			log.Printf("forward create collector (%s): %v", forwardCollectorName, err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
		}
	}
	if err != nil {
		log.Printf("forward create collector (%s): %v", forwardCollectorName, err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward collector").Err()
	}

	tx, err := s.db.BeginTx(ctxReq, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save collector").Err()
	}
	defer func() { _ = tx.Rollback() }()

	credID := uuid.NewString()
	if err := insertUserForwardCredentialSet(ctxReq, tx, box, credID, user.Username, s.forwardCredentialSetNameForCollectorConfig(name), forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      fwdUser,
		Password:      fwdPass,
	}, strings.TrimSpace(created.ID), strings.TrimSpace(created.Username), strings.TrimSpace(created.AuthorizationKey)); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save collector").Err()
	}

	if req.SetDefault {
		if _, err := tx.ExecContext(ctxReq, `UPDATE sf_user_forward_collectors SET is_default=false WHERE username=$1`, user.Username); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to save collector").Err()
		}
	}

	_, err = tx.ExecContext(ctxReq, `INSERT INTO sf_user_forward_collectors (
  id, username, name,
  credential_id,
  base_url, skip_tls_verify, forward_username, forward_password,
  collector_id, collector_username, authorization_key,
  created_at, updated_at, is_default
) VALUES ($1,$2,$3,$4,NULL,$5,NULL,NULL,NULL,NULL,NULL,now(),now(),$6)`,
		configID, user.Username, name,
		credID,
		skipTLSVerify,
		req.SetDefault,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil, errs.B().Code(errs.AlreadyExists).Msg("collector name already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save collector").Err()
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save collector").Err()
	}

	// Deploy (or update) the in-cluster collector with the returned auth key.
	// This can take minutes (PVC provision, image pulls). Run it async so the UI
	// doesn't error out due to request timeouts/cancellation.
	deployName := collectorDeploymentNameForConfig(user.Username, configID, req.SetDefault)
	go func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel2()
		if _, err := ensureCollectorDeployedForName(ctx2, s.cfg, user.Username, deployName, strings.TrimSpace(created.AuthorizationKey), baseURL, skipTLSVerify); err != nil {
			log.Printf("collector deploy (%s): %v", deployName, err)
			// Keep the config saved; user can retry deploy via restart later.
		}
	}()

	return &UserForwardCollectorConfigSummary{
		ID:                configID,
		Name:              name,
		BaseURL:           baseURL,
		SkipTLSVerify:     skipTLSVerify,
		Username:          fwdUser,
		CollectorID:       strings.TrimSpace(created.ID),
		CollectorUsername: strings.TrimSpace(created.Username),
		IsDefault:         req.SetDefault,
	}, nil
}

// DeleteUserForwardCollectorConfig deletes the in-cluster resources for a collector config and removes it from Skyforge.
// It intentionally does NOT delete the Forward-side collector.
//
//encore:api auth method=DELETE path=/api/forward/collector-configs/:id
func (s *Service) DeleteUserForwardCollectorConfig(ctx context.Context, id string) (*DeleteUserForwardCollectorConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_ = migrateLegacyUserForwardCollectorIfNeeded(ctxReq, s.db, user.Username)

	var isDefault bool
	err = s.db.QueryRowContext(ctxReq, `SELECT COALESCE(is_default, false) FROM sf_user_forward_collectors WHERE id=$1 AND username=$2`, id, user.Username).Scan(&isDefault)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &DeleteUserForwardCollectorConfigResponse{Deleted: false}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete collector").Err()
	}

	deployName := collectorDeploymentNameForConfig(user.Username, id, isDefault)
	{
		ctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
		defer cancel2()
		if err := deleteCollectorResourcesByName(ctx2, deployName); err != nil {
			log.Printf("collector delete resources (%s): %v", deployName, err)
		}
	}

	_, err = s.db.ExecContext(ctxReq, `DELETE FROM sf_user_forward_collectors WHERE id=$1 AND username=$2`, id, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete collector").Err()
	}

	// Best-effort cleanup of the legacy single-collector table (used for historical migrations).
	// This avoids deleted collectors reappearing via migrateLegacyUserForwardCollectorIfNeeded.
	if isDefault {
		if _, delErr := s.db.ExecContext(ctxReq, `DELETE FROM sf_user_forward_credentials WHERE username=$1`, user.Username); delErr != nil {
			if !isMissingDBRelation(delErr) {
				log.Printf("collector delete legacy row: %v", delErr)
			}
		}
	}

	return &DeleteUserForwardCollectorConfigResponse{Deleted: true}, nil
}

// GetUserForwardCollectorConfigRuntime returns runtime state for a configured collector.
//
//encore:api auth method=GET path=/api/forward/collector-configs/:id/runtime
func (s *Service) GetUserForwardCollectorConfigRuntime(ctx context.Context, id string) (*collectorRuntimeStatus, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var isDefault bool
	err = s.db.QueryRowContext(ctxReq, `SELECT COALESCE(is_default, false) FROM sf_user_forward_collectors WHERE id=$1 AND username=$2`, id, user.Username).Scan(&isDefault)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &collectorRuntimeStatus{Namespace: kubeNamespace(), DeploymentName: collectorDeploymentNameForConfig(user.Username, id, false)}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector runtime").Err()
	}
	return getCollectorRuntimeStatusByName(ctxReq, collectorDeploymentNameForConfig(user.Username, id, isDefault))
}

type UserCollectorConfigLogsResponse struct {
	Logs string `json:"logs"`
}

type UserCollectorConfigLogsRequest struct {
	Tail int `query:"tail" encore:"optional"`
}

// GetUserForwardCollectorConfigLogs returns the collector's `clientd.log` (or a fallback log) for debugging.
//
//encore:api auth method=GET path=/api/forward/collector-configs/:id/logs
func (s *Service) GetUserForwardCollectorConfigLogs(ctx context.Context, id string, req *UserCollectorConfigLogsRequest) (*UserCollectorConfigLogsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var isDefault bool
	err = s.db.QueryRowContext(ctxReq, `SELECT COALESCE(is_default, false) FROM sf_user_forward_collectors WHERE id=$1 AND username=$2`, id, user.Username).Scan(&isDefault)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &UserCollectorConfigLogsResponse{Logs: ""}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector logs").Err()
	}
	st, err := getCollectorRuntimeStatusByName(ctxReq, collectorDeploymentNameForConfig(user.Username, id, isDefault))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector logs").Err()
	}
	if strings.TrimSpace(st.PodName) == "" {
		return &UserCollectorConfigLogsResponse{Logs: ""}, nil
	}
	tail := 0
	if req != nil {
		tail = req.Tail
	}
	logText, err := getCollectorClientdLog(ctxReq, st.Namespace, st.PodName, tail)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load collector logs").Err()
	}
	return &UserCollectorConfigLogsResponse{Logs: logText}, nil
}

// RestartUserForwardCollectorConfig restarts the collector Deployment (best-effort image update).
//
//encore:api auth method=POST path=/api/forward/collector-configs/:id/restart
func (s *Service) RestartUserForwardCollectorConfig(ctx context.Context, id string) (*collectorRuntimeStatus, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// If the collector isn't deployed yet (common after cluster restarts / image pull delays),
	// "Restart" should act like "Deploy (if missing) then Restart".
	var (
		isDefault     bool
		credID        sql.NullString
		baseURLEnc    sql.NullString
		skipTLSVerify sql.NullBool
		authKeyEnc    sql.NullString
	)
	err = s.db.QueryRowContext(ctxReq, `SELECT COALESCE(is_default, false),
  COALESCE(credential_id,''),
  base_url, COALESCE(skip_tls_verify, false), authorization_key
FROM sf_user_forward_collectors WHERE id=$1 AND username=$2`, id, user.Username).Scan(&isDefault, &credID, &baseURLEnc, &skipTLSVerify, &authKeyEnc)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("collector not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to restart collector").Err()
	}

	deployName := collectorDeploymentNameForConfig(user.Username, id, isDefault)

	// First try a normal restart (fast path).
	if err := restartCollectorDeploymentByName(ctxReq, deployName); err != nil {
		// If the Deployment doesn't exist, deploy it first and then return runtime.
		if strings.Contains(strings.ToLower(err.Error()), "not deployed") {
			box := newSecretBox(s.cfg.SessionSecret)
			baseURL := ""
			authKey := ""
			// Preferred: referenced credential set.
			if strings.TrimSpace(credID.String) != "" {
				if set, err := getUserForwardCredentialSet(ctxReq, s.db, box, user.Username, strings.TrimSpace(credID.String)); err == nil && set != nil {
					baseURL = strings.TrimSpace(set.BaseURL)
					skipTLSVerify.Bool = set.SkipTLSVerify
					skipTLSVerify.Valid = true
					authKey = strings.TrimSpace(set.AuthorizationKey)
				}
			}
			// Fallback: legacy inline columns.
			if strings.TrimSpace(baseURL) == "" && strings.TrimSpace(baseURLEnc.String) != "" {
				if v, err := box.decrypt(baseURLEnc.String); err == nil {
					baseURL = strings.TrimSpace(v)
				}
			}
			if strings.TrimSpace(baseURL) == "" {
				baseURL = defaultForwardBaseURL
			}
			if strings.TrimSpace(authKey) == "" && strings.TrimSpace(authKeyEnc.String) != "" {
				if v, err := box.decrypt(authKeyEnc.String); err == nil {
					authKey = strings.TrimSpace(v)
				}
			}
			if strings.TrimSpace(authKey) == "" {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("collector authorization key missing").Err()
			}

			ctx2, cancel2 := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel2()
			if _, depErr := ensureCollectorDeployedForName(ctx2, s.cfg, user.Username, deployName, authKey, baseURL, skipTLSVerify.Valid && skipTLSVerify.Bool); depErr != nil {
				log.Printf("collector deploy (%s): %v", deployName, depErr)
				return nil, errs.B().Code(errs.Unavailable).Msg("failed to deploy collector").Err()
			}
			// No restart needed after a fresh deploy.
			return getCollectorRuntimeStatusByName(ctxReq, deployName)
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to restart collector").Err()
	}
	return getCollectorRuntimeStatusByName(ctxReq, deployName)
}
