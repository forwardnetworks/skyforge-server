package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// Forward credential sets are stored in sf_credentials with provider='forward'.
// Secrets are encrypted at rest by the application (enc:...).

type forwardCredentialSet struct {
	ID            string
	OwnerUsername string
	WorkspaceID   string
	Name          string

	BaseURL       string
	SkipTLSVerify bool
	Username      string
	Password      string

	CollectorID       string
	CollectorUsername string
	AuthorizationKey  string

	DeviceUsername string
	DevicePassword string

	JumpHost       string
	JumpUsername   string
	JumpPrivateKey string
	JumpCert       string

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (c forwardCredentialSet) toForwardClientCreds() forwardCredentials {
	return forwardCredentials{
		BaseURL:       c.BaseURL,
		SkipTLSVerify: c.SkipTLSVerify,
		Username:      c.Username,
		Password:      c.Password,
		CollectorID:   c.CollectorID,
		CollectorUser: c.CollectorUsername,
	}
}

type forwardCredentialSetCipherRow struct {
	ID            string
	OwnerUsername string
	WorkspaceID   string
	Name          string

	BaseURLEnc       sql.NullString
	SkipTLSVerify    sql.NullBool
	UsernameEnc      sql.NullString
	PasswordEnc      sql.NullString
	CollectorIDEnc   sql.NullString
	CollectorUserEnc sql.NullString
	AuthKeyEnc       sql.NullString

	DeviceUserEnc sql.NullString
	DevicePassEnc sql.NullString

	JumpHostEnc sql.NullString
	JumpUserEnc sql.NullString
	JumpKeyEnc  sql.NullString
	JumpCertEnc sql.NullString

	CreatedAt sql.NullTime
	UpdatedAt sql.NullTime
}

func decryptNullStringOrEmpty(box *secretBox, v sql.NullString) (string, error) {
	s := strings.TrimSpace(v.String)
	if s == "" {
		return "", nil
	}
	if box == nil {
		return "", fmt.Errorf("decrypt: missing box")
	}
	plain, err := box.decrypt(s)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(plain), nil
}

func decodeForwardCredentialSet(box *secretBox, row forwardCredentialSetCipherRow) (*forwardCredentialSet, error) {
	out := &forwardCredentialSet{
		ID:            strings.TrimSpace(row.ID),
		OwnerUsername: strings.ToLower(strings.TrimSpace(row.OwnerUsername)),
		WorkspaceID:   strings.TrimSpace(row.WorkspaceID),
		Name:          strings.TrimSpace(row.Name),
		SkipTLSVerify: row.SkipTLSVerify.Valid && row.SkipTLSVerify.Bool,
	}
	var err error
	if out.BaseURL, err = decryptNullStringOrEmpty(box, row.BaseURLEnc); err != nil {
		return nil, err
	}
	if out.Username, err = decryptNullStringOrEmpty(box, row.UsernameEnc); err != nil {
		return nil, err
	}
	if out.Password, err = decryptNullStringOrEmpty(box, row.PasswordEnc); err != nil {
		return nil, err
	}
	if out.CollectorID, err = decryptNullStringOrEmpty(box, row.CollectorIDEnc); err != nil {
		return nil, err
	}
	if out.CollectorUsername, err = decryptNullStringOrEmpty(box, row.CollectorUserEnc); err != nil {
		return nil, err
	}
	if out.AuthorizationKey, err = decryptNullStringOrEmpty(box, row.AuthKeyEnc); err != nil {
		return nil, err
	}
	if out.DeviceUsername, err = decryptNullStringOrEmpty(box, row.DeviceUserEnc); err != nil {
		return nil, err
	}
	if out.DevicePassword, err = decryptNullStringOrEmpty(box, row.DevicePassEnc); err != nil {
		return nil, err
	}
	if out.JumpHost, err = decryptNullStringOrEmpty(box, row.JumpHostEnc); err != nil {
		return nil, err
	}
	if out.JumpUsername, err = decryptNullStringOrEmpty(box, row.JumpUserEnc); err != nil {
		return nil, err
	}
	if out.JumpPrivateKey, err = decryptNullStringOrEmpty(box, row.JumpKeyEnc); err != nil {
		return nil, err
	}
	if out.JumpCert, err = decryptNullStringOrEmpty(box, row.JumpCertEnc); err != nil {
		return nil, err
	}
	if row.CreatedAt.Valid {
		out.CreatedAt = row.CreatedAt.Time
	}
	if row.UpdatedAt.Valid {
		out.UpdatedAt = row.UpdatedAt.Time
	}
	return out, nil
}

func getUserForwardCredentialSetCipherRow(ctx context.Context, db *sql.DB, ownerUsername, id string) (*forwardCredentialSetCipherRow, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ownerUsername = strings.ToLower(strings.TrimSpace(ownerUsername))
	id = strings.TrimSpace(id)
	if ownerUsername == "" || id == "" {
		return nil, fmt.Errorf("invalid input")
	}
	var row forwardCredentialSetCipherRow
	err := db.QueryRowContext(ctx, `
SELECT id, owner_username, COALESCE(workspace_id, ''), name,
       COALESCE(base_url_enc, ''), COALESCE(skip_tls_verify, false),
       COALESCE(forward_username_enc, ''), COALESCE(forward_password_enc, ''),
       COALESCE(collector_id_enc, ''), COALESCE(collector_username_enc, ''), COALESCE(authorization_key_enc, ''),
       COALESCE(device_username_enc, ''), COALESCE(device_password_enc, ''),
       COALESCE(jump_host_enc, ''), COALESCE(jump_username_enc, ''), COALESCE(jump_private_key_enc, ''), COALESCE(jump_cert_enc, ''),
       created_at, updated_at
  FROM sf_credentials
 WHERE id=$1 AND provider='forward' AND owner_username=$2 AND workspace_id IS NULL
`, id, ownerUsername).Scan(
		&row.ID, &row.OwnerUsername, &row.WorkspaceID, &row.Name,
		&row.BaseURLEnc, &row.SkipTLSVerify,
		&row.UsernameEnc, &row.PasswordEnc,
		&row.CollectorIDEnc, &row.CollectorUserEnc, &row.AuthKeyEnc,
		&row.DeviceUserEnc, &row.DevicePassEnc,
		&row.JumpHostEnc, &row.JumpUserEnc, &row.JumpKeyEnc, &row.JumpCertEnc,
		&row.CreatedAt, &row.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}
	return &row, nil
}

func getUserForwardCredentialSet(ctx context.Context, db *sql.DB, box *secretBox, ownerUsername, id string) (*forwardCredentialSet, error) {
	row, err := getUserForwardCredentialSetCipherRow(ctx, db, ownerUsername, id)
	if err != nil || row == nil {
		return nil, err
	}
	dec, err := decodeForwardCredentialSet(box, *row)
	if err != nil {
		log.Printf("forward credential set decrypt (%s/%s): %v", ownerUsername, id, err)
		return nil, nil
	}
	return dec, nil
}

func getWorkspaceForwardCredentialSetCipherRow(ctx context.Context, db *sql.DB, workspaceID, id string) (*forwardCredentialSetCipherRow, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	id = strings.TrimSpace(id)
	if workspaceID == "" || id == "" {
		return nil, fmt.Errorf("invalid input")
	}
	var row forwardCredentialSetCipherRow
	err := db.QueryRowContext(ctx, `
SELECT id, COALESCE(owner_username, ''), workspace_id, name,
       COALESCE(base_url_enc, ''), COALESCE(skip_tls_verify, false),
       COALESCE(forward_username_enc, ''), COALESCE(forward_password_enc, ''),
       COALESCE(collector_id_enc, ''), COALESCE(collector_username_enc, ''), COALESCE(authorization_key_enc, ''),
       COALESCE(device_username_enc, ''), COALESCE(device_password_enc, ''),
       COALESCE(jump_host_enc, ''), COALESCE(jump_username_enc, ''), COALESCE(jump_private_key_enc, ''), COALESCE(jump_cert_enc, ''),
       created_at, updated_at
  FROM sf_credentials
 WHERE id=$1 AND provider='forward' AND workspace_id=$2 AND owner_username IS NULL
`, id, workspaceID).Scan(
		&row.ID, &row.OwnerUsername, &row.WorkspaceID, &row.Name,
		&row.BaseURLEnc, &row.SkipTLSVerify,
		&row.UsernameEnc, &row.PasswordEnc,
		&row.CollectorIDEnc, &row.CollectorUserEnc, &row.AuthKeyEnc,
		&row.DeviceUserEnc, &row.DevicePassEnc,
		&row.JumpHostEnc, &row.JumpUserEnc, &row.JumpKeyEnc, &row.JumpCertEnc,
		&row.CreatedAt, &row.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}
	return &row, nil
}

func getWorkspaceForwardCredentialSet(ctx context.Context, db *sql.DB, box *secretBox, workspaceID, id string) (*forwardCredentialSet, error) {
	row, err := getWorkspaceForwardCredentialSetCipherRow(ctx, db, workspaceID, id)
	if err != nil || row == nil {
		return nil, err
	}
	dec, err := decodeForwardCredentialSet(box, *row)
	if err != nil {
		log.Printf("workspace forward credential set decrypt (%s/%s): %v", workspaceID, id, err)
		return nil, nil
	}
	return dec, nil
}

func insertUserForwardCredentialSet(ctx context.Context, tx *sql.Tx, box *secretBox, id, ownerUsername, name string, cfg forwardCredentials, collectorID, collectorUsername, authKey string) error {
	if tx == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	id = strings.TrimSpace(id)
	ownerUsername = strings.ToLower(strings.TrimSpace(ownerUsername))
	name = strings.TrimSpace(name)
	if id == "" || ownerUsername == "" || name == "" {
		return fmt.Errorf("invalid input")
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	encBase, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return err
	}
	encUser, err := encryptIfPlain(box, strings.TrimSpace(cfg.Username))
	if err != nil {
		return err
	}
	encPass, err := encryptIfPlain(box, strings.TrimSpace(cfg.Password))
	if err != nil {
		return err
	}
	encCollectorID, err := encryptIfPlain(box, collectorID)
	if err != nil {
		return err
	}
	encCollectorUser, err := encryptIfPlain(box, collectorUsername)
	if err != nil {
		return err
	}
	encAuthKey, err := encryptIfPlain(box, authKey)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO sf_credentials (
  id, owner_username, workspace_id, provider, name,
  base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
  collector_id_enc, collector_username_enc, authorization_key_enc,
  created_at, updated_at
) VALUES ($1,$2,NULL,'forward',$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),now(),now())
`, id, ownerUsername, name, encBase, cfg.SkipTLSVerify, encUser, encPass, encCollectorID, encCollectorUser, encAuthKey)
	return err
}

func upsertUserForwardCredentialSetBasic(ctx context.Context, tx *sql.Tx, box *secretBox, id, ownerUsername, name string, cfg forwardCredentials) error {
	if tx == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	id = strings.TrimSpace(id)
	ownerUsername = strings.ToLower(strings.TrimSpace(ownerUsername))
	name = strings.TrimSpace(name)
	if id == "" || ownerUsername == "" || name == "" {
		return fmt.Errorf("invalid input")
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	encBase, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return err
	}
	encUser, err := encryptIfPlain(box, strings.TrimSpace(cfg.Username))
	if err != nil {
		return err
	}
	encPass, err := encryptIfPlain(box, strings.TrimSpace(cfg.Password))
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO sf_credentials (
  id, owner_username, workspace_id, provider, name,
  base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
  created_at, updated_at
) VALUES ($1,$2,NULL,'forward',$3,$4,$5,$6,$7,now(),now())
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  base_url_enc=excluded.base_url_enc,
  skip_tls_verify=excluded.skip_tls_verify,
  forward_username_enc=excluded.forward_username_enc,
  forward_password_enc=excluded.forward_password_enc,
  updated_at=now()
`, id, ownerUsername, name, encBase, cfg.SkipTLSVerify, encUser, encPass)
	return err
}

func upsertWorkspaceForwardCredentialSet(ctx context.Context, tx *sql.Tx, box *secretBox, id, workspaceID, name string, cfg forwardCredentials) error {
	if tx == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	id = strings.TrimSpace(id)
	workspaceID = strings.TrimSpace(workspaceID)
	name = strings.TrimSpace(name)
	if id == "" || workspaceID == "" || name == "" {
		return fmt.Errorf("invalid input")
	}

	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}

	encBase, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return err
	}
	encUser, err := encryptIfPlain(box, cfg.Username)
	if err != nil {
		return err
	}
	encPass, err := encryptIfPlain(box, cfg.Password)
	if err != nil {
		return err
	}
	encCollectorID, err := encryptIfPlain(box, cfg.CollectorID)
	if err != nil {
		return err
	}
	encCollectorUser, err := encryptIfPlain(box, cfg.CollectorUser)
	if err != nil {
		return err
	}
	encDevUser, err := encryptIfPlain(box, cfg.DeviceUsername)
	if err != nil {
		return err
	}
	encDevPass, err := encryptIfPlain(box, cfg.DevicePassword)
	if err != nil {
		return err
	}
	encJumpHost, err := encryptIfPlain(box, cfg.JumpHost)
	if err != nil {
		return err
	}
	encJumpUser, err := encryptIfPlain(box, cfg.JumpUsername)
	if err != nil {
		return err
	}
	encJumpKey, err := encryptIfPlain(box, cfg.JumpPrivateKey)
	if err != nil {
		return err
	}
	encJumpCert, err := encryptIfPlain(box, cfg.JumpCert)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO sf_credentials (
  id, owner_username, workspace_id, provider, name,
  base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
  collector_id_enc, collector_username_enc,
  device_username_enc, device_password_enc,
  jump_host_enc, jump_username_enc, jump_private_key_enc, jump_cert_enc,
  created_at, updated_at
) VALUES ($1,NULL,$2,'forward',$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),NULLIF($13,''),NULLIF($14,''),NULLIF($15,''),now(),now())
ON CONFLICT (id) DO UPDATE SET
  name=excluded.name,
  base_url_enc=excluded.base_url_enc,
  skip_tls_verify=excluded.skip_tls_verify,
  forward_username_enc=excluded.forward_username_enc,
  forward_password_enc=excluded.forward_password_enc,
  collector_id_enc=excluded.collector_id_enc,
  collector_username_enc=excluded.collector_username_enc,
  device_username_enc=excluded.device_username_enc,
  device_password_enc=excluded.device_password_enc,
  jump_host_enc=excluded.jump_host_enc,
  jump_username_enc=excluded.jump_username_enc,
  jump_private_key_enc=excluded.jump_private_key_enc,
  jump_cert_enc=excluded.jump_cert_enc,
  updated_at=now()
`, id, workspaceID, name, encBase, cfg.SkipTLSVerify, encUser, encPass, encCollectorID, encCollectorUser, encDevUser, encDevPass, encJumpHost, encJumpUser, encJumpKey, encJumpCert)
	return err
}
