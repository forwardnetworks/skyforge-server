package skyforge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev"
	"encore.dev/rlog"

	"encore.app/internal/secretbox"
	"encore.app/internal/skyforgeconfig"
	"encore.app/internal/skyforgedb"

	"encore.app/storage"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidcTypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type RunRequest struct {
	TemplateID  int     `json:"templateId"`
	UserScopeID *string `json:"userId,omitempty"`
	Debug       bool    `json:"debug,omitempty"`
	DryRun      bool    `json:"dryRun,omitempty"`
	Diff        bool    `json:"diff,omitempty"`
	Playbook    string  `json:"playbook,omitempty"`
	Environment JSONMap `json:"environment,omitempty"`
	Limit       string  `json:"limit,omitempty"`
	GitBranch   string  `json:"gitBranch,omitempty"`
	Message     string  `json:"message,omitempty"`
	Arguments   string  `json:"arguments,omitempty"`
	InventoryID *int    `json:"inventoryId,omitempty"`
	Extra       JSONMap `json:"extra,omitempty"`
}

type TemplateSummary struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	UserScopeID string `json:"userId"`
	Repository  string `json:"repository,omitempty"`
	Playbook    string `json:"playbook,omitempty"`
	Description string `json:"description,omitempty"`
	InventoryID int    `json:"inventoryId,omitempty"`
}

type NotificationSettings struct {
	PollingEnabled    bool  `json:"pollingEnabled"`
	PollingIntervalMs int64 `json:"pollingIntervalMs"`
}

type NotificationRecord struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	Type        string    `json:"type"`
	Category    string    `json:"category,omitempty"`
	ReferenceID string    `json:"reference_id,omitempty"`
	Priority    string    `json:"priority,omitempty"`
	IsRead      bool      `json:"is_read"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func externalTemplateRepoByID(ws *UserScope, id string) *ExternalTemplateRepo {
	if ws == nil {
		return nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range ws.ExternalTemplateRepos {
		if strings.EqualFold(strings.TrimSpace(ws.ExternalTemplateRepos[i].ID), id) {
			return &ws.ExternalTemplateRepos[i]
		}
	}
	return nil
}

func externalTemplateRepoByIDForContext(pc *userContext, id string) *ExternalTemplateRepo {
	if pc == nil {
		return nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if pc.userSettings != nil {
		for i := range pc.userSettings.ExternalTemplateRepos {
			if strings.EqualFold(strings.TrimSpace(pc.userSettings.ExternalTemplateRepos[i].ID), id) {
				return &pc.userSettings.ExternalTemplateRepos[i]
			}
		}
	}
	return externalTemplateRepoByID(&pc.userScope, id)
}

type LabSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Owner     string `json:"owner,omitempty"`
	Status    string `json:"status"`
	Provider  string `json:"provider"`
	UpdatedAt string `json:"updatedAt"`
	LaunchURL string `json:"launchUrl,omitempty"`
}

func readOptionalFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func isSafeRelativePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return true
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return false
	}
	parts := strings.SplitSeq(path, "/")
	for p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func userScopePrimaryOwner(p UserScope) string {
	if strings.TrimSpace(p.CreatedBy) != "" {
		return strings.TrimSpace(p.CreatedBy)
	}
	if len(p.Owners) > 0 {
		return strings.TrimSpace(p.Owners[0])
	}
	return ""
}

func normalizeNetlabServer(s NetlabServerConfig, fallback NetlabConfig) NetlabServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.SSHKeyFile = strings.TrimSpace(s.SSHKeyFile)
	s.StateRoot = strings.TrimSpace(s.StateRoot)
	s.APIURL = strings.TrimRight(strings.TrimSpace(s.APIURL), "/")
	s.ContainerlabAPIURL = strings.TrimRight(strings.TrimSpace(s.ContainerlabAPIURL), "/")

	if s.SSHHost == "" && s.APIURL != "" {
		if u, err := url.Parse(s.APIURL); err == nil && u != nil {
			s.SSHHost = strings.TrimSpace(u.Hostname())
		}
	}
	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.SSHUser)
	}
	if s.SSHKeyFile == "" {
		s.SSHKeyFile = strings.TrimSpace(fallback.SSHKeyFile)
	}
	if s.StateRoot == "" {
		s.StateRoot = strings.TrimSpace(fallback.StateRoot)
	}
	if s.APIURL == "" && s.SSHHost != "" {
		s.APIURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", s.SSHHost), "/")
	}
	if s.Name == "" {
		if s.SSHHost != "" {
			s.Name = s.SSHHost
		} else {
			s.Name = "netlab-default"
		}
	}
	return s
}

type userScopesStore interface {
	load() ([]UserScope, error)
	upsert(userScope UserScope) error
	delete(userScopeID string) error
}

type usersStore interface {
	load() ([]string, error)
	upsert(username string) error
	remove(username string) error
}

type secretBox struct {
	box *secretbox.Box
}

func newSecretBox(secret string) *secretBox {
	return &secretBox{box: secretbox.New(secret)}
}

func (sb *secretBox) encrypt(plaintext string) (string, error) {
	if sb == nil || sb.box == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	return sb.box.Encrypt(plaintext)
}

func (sb *secretBox) decrypt(value string) (string, error) {
	if sb == nil || sb.box == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	return sb.box.Decrypt(value)
}

type awsSSOTokenRecord struct {
	StartURL               string    `json:"startUrl"`
	Region                 string    `json:"region"`
	ClientID               string    `json:"clientId,omitempty"`
	ClientSecret           string    `json:"clientSecret,omitempty"`
	ClientSecretExpiresAt  time.Time `json:"clientSecretExpiresAt"`
	AccessToken            string    `json:"accessToken,omitempty"`
	AccessTokenExpiresAt   time.Time `json:"accessTokenExpiresAt"`
	RefreshToken           string    `json:"refreshToken,omitempty"`
	RefreshTokenExpiresAt  time.Time `json:"refreshTokenExpiresAt"`
	LastAuthenticatedAtUTC time.Time `json:"lastAuthenticatedAtUtc"`
}

type awsSSOTokenStore interface {
	get(username string) (*awsSSOTokenRecord, error)
	put(username string, rec awsSSOTokenRecord) error
	clear(username string) error
	loadAll() (map[string]awsSSOTokenRecord, error)
}

type pgUsersStore struct {
	db *sql.DB
}

func newPGUsersStore(db *sql.DB) *pgUsersStore {
	return &pgUsersStore{db: db}
}

func (s *pgUsersStore) load() ([]string, error) {
	rows, err := s.db.Query(`SELECT username FROM sf_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		out = append(out, username)
	}
	return out, rows.Err()
}

func (s *pgUsersStore) upsert(username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if !isValidUsername(username) {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO sf_users (username, last_seen_at) VALUES ($1, now())
ON CONFLICT (username) DO UPDATE SET last_seen_at=excluded.last_seen_at`, username)
	return err
}

func (s *pgUsersStore) remove(username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sf_users WHERE username = $1`, username)
	return err
}

type pgAWSStore struct {
	db  *sql.DB
	box *secretBox
}

func newPGAWSStore(db *sql.DB, box *secretBox) *pgAWSStore {
	return &pgAWSStore{db: db, box: box}
}

func encryptIfPlain(box *secretBox, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "enc:") {
		return value, nil
	}
	return box.encrypt(value)
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func (s *pgAWSStore) loadAll() (map[string]awsSSOTokenRecord, error) {
	rows, err := s.db.Query(`SELECT username, start_url, region, client_id, client_secret, client_secret_expires_at,
access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, last_authenticated_at_utc
FROM sf_aws_sso_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]awsSSOTokenRecord{}
	for rows.Next() {
		var (
			username, startURL, region                                         string
			clientID                                                           sql.NullString
			clientSecret, accessToken, refreshToken                            sql.NullString
			clientSecretExpiresAt, accessTokenExpiresAt, refreshTokenExpiresAt sql.NullTime
			lastAuthenticatedAt                                                sql.NullTime
		)
		if err := rows.Scan(&username, &startURL, &region, &clientID, &clientSecret, &clientSecretExpiresAt, &accessToken, &accessTokenExpiresAt, &refreshToken, &refreshTokenExpiresAt, &lastAuthenticatedAt); err != nil {
			return nil, err
		}
		rec := awsSSOTokenRecord{
			StartURL:     startURL,
			Region:       region,
			ClientID:     clientID.String,
			ClientSecret: clientSecret.String,
			AccessToken:  accessToken.String,
			RefreshToken: refreshToken.String,
		}
		if clientSecretExpiresAt.Valid {
			rec.ClientSecretExpiresAt = clientSecretExpiresAt.Time
		}
		if accessTokenExpiresAt.Valid {
			rec.AccessTokenExpiresAt = accessTokenExpiresAt.Time
		}
		if refreshTokenExpiresAt.Valid {
			rec.RefreshTokenExpiresAt = refreshTokenExpiresAt.Time
		}
		if lastAuthenticatedAt.Valid {
			rec.LastAuthenticatedAtUTC = lastAuthenticatedAt.Time
		}
		out[username] = rec
	}
	return out, rows.Err()
}

func (s *pgAWSStore) get(username string) (*awsSSOTokenRecord, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var (
		startURL, region                                                   string
		clientID                                                           sql.NullString
		clientSecret, accessToken, refreshToken                            sql.NullString
		clientSecretExpiresAt, accessTokenExpiresAt, refreshTokenExpiresAt sql.NullTime
		lastAuthenticatedAt                                                sql.NullTime
	)
	err := s.db.QueryRow(`SELECT start_url, region, client_id, client_secret, client_secret_expires_at,
access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, last_authenticated_at_utc
FROM sf_aws_sso_tokens WHERE username=$1`, username).Scan(
		&startURL, &region, &clientID, &clientSecret, &clientSecretExpiresAt,
		&accessToken, &accessTokenExpiresAt, &refreshToken, &refreshTokenExpiresAt, &lastAuthenticatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rec := awsSSOTokenRecord{
		StartURL:     startURL,
		Region:       region,
		ClientID:     clientID.String,
		ClientSecret: clientSecret.String,
		AccessToken:  accessToken.String,
		RefreshToken: refreshToken.String,
	}
	if clientSecretExpiresAt.Valid {
		rec.ClientSecretExpiresAt = clientSecretExpiresAt.Time
	}
	if accessTokenExpiresAt.Valid {
		rec.AccessTokenExpiresAt = accessTokenExpiresAt.Time
	}
	if refreshTokenExpiresAt.Valid {
		rec.RefreshTokenExpiresAt = refreshTokenExpiresAt.Time
	}
	if lastAuthenticatedAt.Valid {
		rec.LastAuthenticatedAtUTC = lastAuthenticatedAt.Time
	}
	if rec.AccessToken != "" {
		if decrypted, err := s.box.decrypt(rec.AccessToken); err == nil {
			rec.AccessToken = decrypted
		}
	}
	if rec.RefreshToken != "" {
		if decrypted, err := s.box.decrypt(rec.RefreshToken); err == nil {
			rec.RefreshToken = decrypted
		}
	}
	if rec.ClientSecret != "" {
		if decrypted, err := s.box.decrypt(rec.ClientSecret); err == nil {
			rec.ClientSecret = decrypted
		}
	}
	return &rec, nil
}

func (s *pgAWSStore) put(username string, rec awsSSOTokenRecord) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return fmt.Errorf("username is required")
	}
	isSystemKey := strings.HasPrefix(username, "__client__:")
	if !isSystemKey && !isValidUsername(username) {
		return nil
	}
	if !isSystemKey {
		if _, err := s.db.Exec(`INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, username); err != nil {
			return err
		}
	}

	clientSecret, err := encryptIfPlain(s.box, rec.ClientSecret)
	if err != nil {
		return err
	}
	accessToken, err := encryptIfPlain(s.box, rec.AccessToken)
	if err != nil {
		return err
	}
	refreshToken, err := encryptIfPlain(s.box, rec.RefreshToken)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`INSERT INTO sf_aws_sso_tokens (
  username, start_url, region, client_id, client_secret, client_secret_expires_at,
  access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, last_authenticated_at_utc, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
ON CONFLICT (username) DO UPDATE SET
  start_url=excluded.start_url,
  region=excluded.region,
  client_id=excluded.client_id,
  client_secret=excluded.client_secret,
  client_secret_expires_at=excluded.client_secret_expires_at,
  access_token=excluded.access_token,
  access_token_expires_at=excluded.access_token_expires_at,
  refresh_token=excluded.refresh_token,
  refresh_token_expires_at=excluded.refresh_token_expires_at,
  last_authenticated_at_utc=excluded.last_authenticated_at_utc,
  updated_at=now()`,
		username, strings.TrimSpace(rec.StartURL), strings.TrimSpace(rec.Region), nullIfEmpty(strings.TrimSpace(rec.ClientID)),
		nullIfEmpty(clientSecret), nullTime(rec.ClientSecretExpiresAt),
		nullIfEmpty(accessToken), nullTime(rec.AccessTokenExpiresAt),
		nullIfEmpty(refreshToken), nullTime(rec.RefreshTokenExpiresAt),
		nullTime(rec.LastAuthenticatedAtUTC),
	)
	return err
}

func (s *pgAWSStore) clear(username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sf_aws_sso_tokens WHERE username=$1`, username)
	return err
}

type pgUserScopesStore struct {
	db *sql.DB
}

func newPGUserScopesStore(db *sql.DB) *pgUserScopesStore {
	return &pgUserScopesStore{db: db}
}

type awsStaticCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	UpdatedAt       time.Time
}

type azureServicePrincipal struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
	UpdatedAt      time.Time
}

type gcpServiceAccount struct {
	ServiceAccountJSON string
	ProjectIDOverride  string
	UpdatedAt          time.Time
}

type AuditEvent struct {
	ID               int64     `json:"id"`
	CreatedAt        time.Time `json:"createdAt"`
	ActorUsername    string    `json:"actorUsername"`
	ActorIsAdmin     bool      `json:"actorIsAdmin"`
	ImpersonatedUser string    `json:"impersonatedUsername,omitempty"`
	Action           string    `json:"action"`
	UserScopeID      string    `json:"userId,omitempty"`
	Details          string    `json:"details,omitempty"`
}

func auditRequestDetails(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if ip == "" {
		ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	details := map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
		"host":   r.Host,
		"proto":  r.Proto,
		"ip":     ip,
		"ua":     r.UserAgent(),
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); v != "" {
		details["x_forwarded_proto"] = v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); v != "" {
		details["x_forwarded_host"] = v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Uri")); v != "" {
		details["x_forwarded_uri"] = v
	}
	if v := strings.TrimSpace(r.Referer()); v != "" {
		details["referer"] = v
	}
	b, _ := json.Marshal(details)
	return string(b)
}

func ensureAuditActor(ctx context.Context, db *sql.DB, username string) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || db == nil {
		return
	}
	_, _ = db.ExecContext(ctx, `INSERT INTO sf_users (username, created_at) VALUES ($1, now()) ON CONFLICT (username) DO NOTHING`, username)
}

func writeAuditEvent(ctx context.Context, db *sql.DB, actor string, actorIsAdmin bool, impersonated string, action string, userScopeID string, details string) {
	if db == nil {
		return
	}
	actor = strings.ToLower(strings.TrimSpace(actor))
	impersonated = strings.ToLower(strings.TrimSpace(impersonated))
	action = strings.TrimSpace(action)
	userScopeID = strings.TrimSpace(userScopeID)
	details = strings.TrimSpace(details)
	if actor == "" || action == "" {
		return
	}
	ensureAuditActor(ctx, db, actor)
	if impersonated != "" {
		ensureAuditActor(ctx, db, impersonated)
	}
	if len(details) > 4000 {
		details = details[:4000]
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_audit_log (
  actor_username, actor_is_admin, impersonated_username, action, user_id, details
) VALUES ($1,$2,NULLIF($3,''),$4,NULLIF($5,''),NULLIF($6,''))`,
		actor, actorIsAdmin, impersonated, action, userScopeID, details,
	)
	if err != nil {
		log.Printf("audit log insert failed: %v", err)
	}
}

func getWorkspaceAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string) (*awsStaticCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil, fmt.Errorf("user scope id is required")
	}
	var akid, sak, st sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT access_key_id, secret_access_key, session_token, updated_at
FROM sf_user_scope_aws_static_credentials WHERE user_id=$1`, userScopeID).Scan(&akid, &sak, &st, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	accessKeyID, err := box.decrypt(akid.String)
	if err != nil {
		return nil, err
	}
	secretAccessKey, err := box.decrypt(sak.String)
	if err != nil {
		return nil, err
	}
	sessionToken, err := box.decrypt(st.String)
	if err != nil {
		return nil, err
	}
	rec := &awsStaticCredentials{
		AccessKeyID:     strings.TrimSpace(accessKeyID),
		SecretAccessKey: strings.TrimSpace(secretAccessKey),
		SessionToken:    strings.TrimSpace(sessionToken),
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string, accessKeyID string, secretAccessKey string, sessionToken string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	accessKeyID = strings.TrimSpace(accessKeyID)
	secretAccessKey = strings.TrimSpace(secretAccessKey)
	sessionToken = strings.TrimSpace(sessionToken)
	if userScopeID == "" {
		return fmt.Errorf("user scope id is required")
	}
	if accessKeyID == "" || secretAccessKey == "" {
		return fmt.Errorf("accessKeyId and secretAccessKey are required")
	}
	encAKID, err := encryptIfPlain(box, accessKeyID)
	if err != nil {
		return err
	}
	encSAK, err := encryptIfPlain(box, secretAccessKey)
	if err != nil {
		return err
	}
	encST, err := encryptIfPlain(box, sessionToken)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_scope_aws_static_credentials (user_id, access_key_id, secret_access_key, session_token, updated_at)
VALUES ($1,$2,$3,NULLIF($4,''),now())
ON CONFLICT (user_id) DO UPDATE SET
  access_key_id=excluded.access_key_id,
  secret_access_key=excluded.secret_access_key,
  session_token=excluded.session_token,
  updated_at=now()`, userScopeID, encAKID, encSAK, encST)
	return err
}

func deleteWorkspaceAWSStaticCredentials(ctx context.Context, db *sql.DB, userScopeID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_scope_aws_static_credentials WHERE user_id=$1`, userScopeID)
	return err
}

type forwardCredentials struct {
	BaseURL        string
	SkipTLSVerify  bool
	Username       string
	Password       string
	CollectorID    string
	CollectorUser  string
	DeviceUsername string
	DevicePassword string
	JumpHost       string
	JumpUsername   string
	JumpPrivateKey string
	JumpCert       string
	UpdatedAt      time.Time
}

func getWorkspaceForwardCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string) (*forwardCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil, fmt.Errorf("user scope id is required")
	}
	var baseURL, username, password sql.NullString
	var collectorID, collectorUser sql.NullString
	var deviceUser, devicePass sql.NullString
	var jumpHost, jumpUser, jumpKey, jumpCert sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT base_url, username, password,
  COALESCE(collector_id, ''), COALESCE(collector_username, ''),
  COALESCE(device_username, ''), COALESCE(device_password, ''),
  COALESCE(jump_host, ''), COALESCE(jump_username, ''), COALESCE(jump_private_key, ''), COALESCE(jump_cert, ''),
  updated_at
FROM sf_user_scope_forward_credentials WHERE user_id=$1`, userScopeID).Scan(
		&baseURL,
		&username,
		&password,
		&collectorID,
		&collectorUser,
		&deviceUser,
		&devicePass,
		&jumpHost,
		&jumpUser,
		&jumpKey,
		&jumpCert,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	baseURLValue, err := box.decrypt(baseURL.String)
	if err != nil {
		return nil, nil
	}
	usernameValue, err := box.decrypt(username.String)
	if err != nil {
		return nil, nil
	}
	passwordValue, err := box.decrypt(password.String)
	if err != nil {
		return nil, nil
	}
	collectorIDValue, err := box.decrypt(collectorID.String)
	if err != nil {
		return nil, nil
	}
	collectorUserValue, err := box.decrypt(collectorUser.String)
	if err != nil {
		return nil, nil
	}
	deviceUserValue, err := box.decrypt(deviceUser.String)
	if err != nil {
		return nil, nil
	}
	devicePassValue, err := box.decrypt(devicePass.String)
	if err != nil {
		return nil, nil
	}
	jumpHostValue, err := box.decrypt(jumpHost.String)
	if err != nil {
		return nil, nil
	}
	jumpUserValue, err := box.decrypt(jumpUser.String)
	if err != nil {
		return nil, nil
	}
	jumpKeyValue, err := box.decrypt(jumpKey.String)
	if err != nil {
		return nil, nil
	}
	jumpCertValue, err := box.decrypt(jumpCert.String)
	if err != nil {
		return nil, nil
	}
	rec := &forwardCredentials{
		BaseURL:        strings.TrimSpace(baseURLValue),
		Username:       strings.TrimSpace(usernameValue),
		Password:       strings.TrimSpace(passwordValue),
		CollectorID:    strings.TrimSpace(collectorIDValue),
		CollectorUser:  strings.TrimSpace(collectorUserValue),
		DeviceUsername: strings.TrimSpace(deviceUserValue),
		DevicePassword: strings.TrimSpace(devicePassValue),
		JumpHost:       strings.TrimSpace(jumpHostValue),
		JumpUsername:   strings.TrimSpace(jumpUserValue),
		JumpPrivateKey: strings.TrimSpace(jumpKeyValue),
		JumpCert:       strings.TrimSpace(jumpCertValue),
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceForwardCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string, rec forwardCredentials) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return fmt.Errorf("user scope id is required")
	}
	baseURL := strings.TrimSpace(rec.BaseURL)
	username := strings.TrimSpace(rec.Username)
	password := strings.TrimSpace(rec.Password)
	if baseURL == "" || username == "" || password == "" {
		return fmt.Errorf("baseUrl, username, and password are required")
	}
	encBaseURL, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return err
	}
	encUser, err := encryptIfPlain(box, username)
	if err != nil {
		return err
	}
	encPass, err := encryptIfPlain(box, password)
	if err != nil {
		return err
	}
	encCollectorID, err := encryptIfPlain(box, rec.CollectorID)
	if err != nil {
		return err
	}
	encCollectorUser, err := encryptIfPlain(box, rec.CollectorUser)
	if err != nil {
		return err
	}
	encDeviceUser, err := encryptIfPlain(box, rec.DeviceUsername)
	if err != nil {
		return err
	}
	encDevicePass, err := encryptIfPlain(box, rec.DevicePassword)
	if err != nil {
		return err
	}
	encJumpHost, err := encryptIfPlain(box, rec.JumpHost)
	if err != nil {
		return err
	}
	encJumpUser, err := encryptIfPlain(box, rec.JumpUsername)
	if err != nil {
		return err
	}
	encJumpKey, err := encryptIfPlain(box, rec.JumpPrivateKey)
	if err != nil {
		return err
	}
	encJumpCert, err := encryptIfPlain(box, rec.JumpCert)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_scope_forward_credentials (
  user_id, base_url, username, password,
  collector_id, collector_username,
  device_username, device_password,
  jump_host, jump_username, jump_private_key, jump_cert,
  updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),now())
ON CONFLICT (user_id) DO UPDATE SET
  base_url=excluded.base_url,
  username=excluded.username,
  password=excluded.password,
  collector_id=excluded.collector_id,
  collector_username=excluded.collector_username,
  device_username=excluded.device_username,
  device_password=excluded.device_password,
  jump_host=excluded.jump_host,
  jump_username=excluded.jump_username,
  jump_private_key=excluded.jump_private_key,
  jump_cert=excluded.jump_cert,
  updated_at=now()`,
		userScopeID,
		encBaseURL,
		encUser,
		encPass,
		encCollectorID,
		encCollectorUser,
		encDeviceUser,
		encDevicePass,
		encJumpHost,
		encJumpUser,
		encJumpKey,
		encJumpCert,
	)
	return err
}

func deleteWorkspaceForwardCredentials(ctx context.Context, db *sql.DB, userScopeID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_scope_forward_credentials WHERE user_id=$1`, userScopeID)
	return err
}

func getWorkspaceAzureCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string) (*azureServicePrincipal, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil, fmt.Errorf("user scope id is required")
	}
	var tenantID, clientID, clientSecret, subscriptionID sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT tenant_id, client_id, client_secret, COALESCE(subscription_id, ''), updated_at
FROM sf_user_scope_azure_credentials WHERE user_id=$1`, userScopeID).Scan(&tenantID, &clientID, &clientSecret, &subscriptionID, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	tenantValue, err := box.decrypt(tenantID.String)
	if err != nil {
		return nil, err
	}
	clientValue, err := box.decrypt(clientID.String)
	if err != nil {
		return nil, err
	}
	secretValue, err := box.decrypt(clientSecret.String)
	if err != nil {
		return nil, err
	}
	subscriptionValue := strings.TrimSpace(subscriptionID.String)
	if subscriptionValue != "" {
		if decrypted, err := box.decrypt(subscriptionValue); err == nil {
			subscriptionValue = decrypted
		}
	}
	rec := &azureServicePrincipal{
		TenantID:       strings.TrimSpace(tenantValue),
		ClientID:       strings.TrimSpace(clientValue),
		ClientSecret:   strings.TrimSpace(secretValue),
		SubscriptionID: strings.TrimSpace(subscriptionValue),
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceAzureCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string, cred azureServicePrincipal) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return fmt.Errorf("user scope id is required")
	}
	cred.TenantID = strings.TrimSpace(cred.TenantID)
	cred.ClientID = strings.TrimSpace(cred.ClientID)
	cred.ClientSecret = strings.TrimSpace(cred.ClientSecret)
	cred.SubscriptionID = strings.TrimSpace(cred.SubscriptionID)
	if cred.TenantID == "" || cred.ClientID == "" || cred.ClientSecret == "" {
		return fmt.Errorf("tenantId, clientId, and clientSecret are required")
	}
	encTenant, err := encryptIfPlain(box, cred.TenantID)
	if err != nil {
		return err
	}
	encClient, err := encryptIfPlain(box, cred.ClientID)
	if err != nil {
		return err
	}
	encSecret, err := encryptIfPlain(box, cred.ClientSecret)
	if err != nil {
		return err
	}
	encSubscription := ""
	if cred.SubscriptionID != "" {
		encSubscription, err = encryptIfPlain(box, cred.SubscriptionID)
		if err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_scope_azure_credentials (
  user_id, tenant_id, client_id, client_secret, subscription_id, updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),now())
ON CONFLICT (user_id) DO UPDATE SET
  tenant_id=excluded.tenant_id,
  client_id=excluded.client_id,
  client_secret=excluded.client_secret,
  subscription_id=excluded.subscription_id,
  updated_at=now()`, userScopeID, encTenant, encClient, encSecret, encSubscription)
	return err
}

func deleteWorkspaceAzureCredentials(ctx context.Context, db *sql.DB, userScopeID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_scope_azure_credentials WHERE user_id=$1`, userScopeID)
	return err
}

func getWorkspaceGCPCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string) (*gcpServiceAccount, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil, fmt.Errorf("user scope id is required")
	}
	var raw sql.NullString
	var projectOverride sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT service_account_json, COALESCE(project_id_override, ''), updated_at
FROM sf_user_scope_gcp_credentials WHERE user_id=$1`, userScopeID).Scan(&raw, &projectOverride, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decoded, err := box.decrypt(raw.String)
	if err != nil {
		return nil, err
	}
	rec := &gcpServiceAccount{ServiceAccountJSON: strings.TrimSpace(decoded), ProjectIDOverride: strings.TrimSpace(projectOverride.String)}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceGCPCredentials(ctx context.Context, db *sql.DB, box *secretBox, userScopeID string, jsonBlob string, projectOverride string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	jsonBlob = strings.TrimSpace(jsonBlob)
	projectOverride = strings.TrimSpace(projectOverride)
	if userScopeID == "" {
		return fmt.Errorf("user scope id is required")
	}
	if jsonBlob == "" {
		return fmt.Errorf("service identity json is required")
	}
	encJSON, err := encryptIfPlain(box, jsonBlob)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_scope_gcp_credentials (
  user_id, service_account_json, project_id_override, updated_at
) VALUES ($1,$2,NULLIF($3,''),now())
ON CONFLICT (user_id) DO UPDATE SET
  service_account_json=excluded.service_account_json,
  project_id_override=excluded.project_id_override,
  updated_at=now()`, userScopeID, encJSON, projectOverride)
	return err
}

func deleteWorkspaceGCPCredentials(ctx context.Context, db *sql.DB, userScopeID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_scope_gcp_credentials WHERE user_id=$1`, userScopeID)
	return err
}

func (s *pgUserScopesStore) load() ([]UserScope, error) {
	rows, err := s.db.Query(`SELECT id, slug, name, description, created_at, created_by,
		blueprint, default_branch, terraform_state_key, terraform_init_template_id, terraform_plan_template_id, terraform_apply_template_id, ansible_run_template_id, netlab_run_template_id, eve_ng_run_template_id, containerlab_run_template_id,
		aws_account_id, aws_role_name, aws_region, aws_auth_method, artifacts_bucket, is_public,
		eve_server, netlab_server, allow_external_template_repos, allow_custom_eve_servers, allow_custom_netlab_servers, allow_custom_containerlab_servers, external_template_repos, gitea_owner, gitea_repo
	FROM sf_user_scopes ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userScopes := []UserScope{}
	userScopeByID := map[string]*UserScope{}
	for rows.Next() {
		var (
			id, slug, name, createdBy                                                                      string
			description, blueprint, defaultBranch                                                          sql.NullString
			terraformStateKey                                                                              sql.NullString
			terraformInit, terraformPlan, terraformApply, ansibleRun, netlabRun, eveNgRun, containerlabRun sql.NullInt64
			awsAccountID, awsRoleName, awsRegion, awsAuthMethod                                            sql.NullString
			artifactsBucket                                                                                sql.NullString
			isPublic                                                                                       bool
			eveServer                                                                                      sql.NullString
			netlabServer                                                                                   sql.NullString
			allowExternalTemplateRepos                                                                     bool
			allowCustomEveServers                                                                          bool
			allowCustomNetlabServers                                                                       bool
			allowCustomContainerlabServers                                                                 bool
			externalTemplateReposJSON                                                                      []byte
			createdAt                                                                                      time.Time
			giteaOwner, giteaRepo                                                                          string
		)
		if err := rows.Scan(&id, &slug, &name, &description, &createdAt, &createdBy,
			&blueprint, &defaultBranch, &terraformStateKey, &terraformInit, &terraformPlan, &terraformApply, &ansibleRun, &netlabRun, &eveNgRun, &containerlabRun,
			&awsAccountID, &awsRoleName, &awsRegion, &awsAuthMethod, &artifactsBucket, &isPublic,
			&eveServer, &netlabServer, &allowExternalTemplateRepos, &allowCustomEveServers, &allowCustomNetlabServers, &allowCustomContainerlabServers, &externalTemplateReposJSON, &giteaOwner, &giteaRepo,
		); err != nil {
			return nil, err
		}
		var externalTemplateRepos []ExternalTemplateRepo
		if len(externalTemplateReposJSON) > 0 {
			_ = json.Unmarshal(externalTemplateReposJSON, &externalTemplateRepos)
		}
		p := UserScope{
			ID:                             id,
			Slug:                           slug,
			Name:                           name,
			Description:                    description.String,
			CreatedAt:                      createdAt,
			CreatedBy:                      createdBy,
			Blueprint:                      blueprint.String,
			DefaultBranch:                  defaultBranch.String,
			TerraformStateKey:              terraformStateKey.String,
			TerraformInitTemplateID:        int(terraformInit.Int64),
			TerraformPlanTemplateID:        int(terraformPlan.Int64),
			TerraformApplyTemplateID:       int(terraformApply.Int64),
			AnsibleRunTemplateID:           int(ansibleRun.Int64),
			NetlabRunTemplateID:            int(netlabRun.Int64),
			EveNgRunTemplateID:             int(eveNgRun.Int64),
			ContainerlabRunTemplateID:      int(containerlabRun.Int64),
			AWSAccountID:                   awsAccountID.String,
			AWSRoleName:                    awsRoleName.String,
			AWSRegion:                      awsRegion.String,
			AWSAuthMethod:                  awsAuthMethod.String,
			ArtifactsBucket:                artifactsBucket.String,
			IsPublic:                       isPublic,
			EveServer:                      eveServer.String,
			NetlabServer:                   netlabServer.String,
			AllowExternalTemplateRepos:     allowExternalTemplateRepos,
			AllowCustomEveServers:          allowCustomEveServers,
			AllowCustomNetlabServers:       allowCustomNetlabServers,
			AllowCustomContainerlabServers: allowCustomContainerlabServers,
			ExternalTemplateRepos:          externalTemplateRepos,
			GiteaOwner:                     giteaOwner,
			GiteaRepo:                      giteaRepo,
		}
		userScopes = append(userScopes, p)
		userScopeByID[id] = &userScopes[len(userScopes)-1]
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	memberRows, err := s.db.Query(`SELECT user_id, username, role FROM sf_user_scope_members ORDER BY user_id, username`)
	if err != nil {
		return nil, err
	}
	defer memberRows.Close()
	for memberRows.Next() {
		var userScopeID, username, role string
		if err := memberRows.Scan(&userScopeID, &username, &role); err != nil {
			return nil, err
		}
		p := userScopeByID[userScopeID]
		if p == nil {
			continue
		}
		switch role {
		case "owner":
			p.Owners = append(p.Owners, username)
		case "editor":
			p.Editors = append(p.Editors, username)
		case "viewer":
			p.Viewers = append(p.Viewers, username)
		}
	}
	if err := memberRows.Err(); err != nil {
		return nil, err
	}

	groupRows, err := s.db.Query(`SELECT user_id, group_name, role FROM sf_user_scope_groups ORDER BY user_id, group_name`)
	if err != nil {
		return nil, err
	}
	defer groupRows.Close()
	for groupRows.Next() {
		var userScopeID, groupName, role string
		if err := groupRows.Scan(&userScopeID, &groupName, &role); err != nil {
			return nil, err
		}
		p := userScopeByID[userScopeID]
		if p == nil {
			continue
		}
		switch role {
		case "owner":
			p.OwnerGroups = append(p.OwnerGroups, groupName)
		case "editor":
			p.EditorGroups = append(p.EditorGroups, groupName)
		case "viewer":
			p.ViewerGroups = append(p.ViewerGroups, groupName)
		}
	}
	if err := groupRows.Err(); err != nil {
		return nil, err
	}
	return userScopes, nil
}

func (s *pgUserScopesStore) upsert(userScope UserScope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	id := strings.TrimSpace(userScope.ID)
	if id == "" {
		return fmt.Errorf("user scope id is required")
	}
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext($1))`, id); err != nil {
		return err
	}

	ensureUser := func(username string) error {
		username = strings.ToLower(strings.TrimSpace(username))
		if username == "" || !isValidUsername(username) {
			return nil
		}
		_, err := tx.Exec(`INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, username)
		return err
	}

	if err := ensureUser(userScope.CreatedBy); err != nil {
		return err
	}
	for _, u := range append(append([]string{}, userScope.Owners...), append(userScope.Editors, userScope.Viewers...)...) {
		if err := ensureUser(u); err != nil {
			return err
		}
	}

	slug := strings.TrimSpace(userScope.Slug)
	if slug == "" {
		slug = slugify(userScope.Name)
	}
	createdBy := strings.ToLower(strings.TrimSpace(userScope.CreatedBy))
	if createdBy == "" {
		return fmt.Errorf("user-scope createdBy is required")
	}
	externalTemplateReposJSON, err := json.Marshal(userScope.ExternalTemplateRepos)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO sf_user_scopes (
		  id, slug, name, description, created_at, created_by,
		  allow_external_template_repos, allow_custom_eve_servers, allow_custom_netlab_servers, allow_custom_containerlab_servers, external_template_repos,
		  blueprint, default_branch, terraform_state_key, terraform_init_template_id, terraform_plan_template_id, terraform_apply_template_id, ansible_run_template_id, netlab_run_template_id, eve_ng_run_template_id, containerlab_run_template_id,
		  aws_account_id, aws_role_name, aws_region, aws_auth_method, artifacts_bucket, is_public,
		  eve_server, netlab_server, gitea_owner, gitea_repo, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,now())
		ON CONFLICT (id) DO UPDATE SET
		  slug=excluded.slug,
		  name=excluded.name,
		  description=excluded.description,
		  allow_external_template_repos=excluded.allow_external_template_repos,
		  allow_custom_eve_servers=excluded.allow_custom_eve_servers,
		  allow_custom_netlab_servers=excluded.allow_custom_netlab_servers,
		  allow_custom_containerlab_servers=excluded.allow_custom_containerlab_servers,
		  external_template_repos=excluded.external_template_repos,
		  blueprint=excluded.blueprint,
		  default_branch=excluded.default_branch,
		  terraform_state_key=excluded.terraform_state_key,
		  terraform_init_template_id=excluded.terraform_init_template_id,
		  terraform_plan_template_id=excluded.terraform_plan_template_id,
		  terraform_apply_template_id=excluded.terraform_apply_template_id,
		  ansible_run_template_id=excluded.ansible_run_template_id,
		  netlab_run_template_id=excluded.netlab_run_template_id,
		  eve_ng_run_template_id=excluded.eve_ng_run_template_id,
		  containerlab_run_template_id=excluded.containerlab_run_template_id,
		  aws_account_id=excluded.aws_account_id,
		  aws_role_name=excluded.aws_role_name,
		  aws_region=excluded.aws_region,
		  aws_auth_method=excluded.aws_auth_method,
		  artifacts_bucket=excluded.artifacts_bucket,
		  is_public=excluded.is_public,
		  eve_server=excluded.eve_server,
		  netlab_server=excluded.netlab_server,
		  gitea_owner=excluded.gitea_owner,
		  gitea_repo=excluded.gitea_repo,
		  updated_at=now()`,
		id, slug, strings.TrimSpace(userScope.Name), nullIfEmpty(strings.TrimSpace(userScope.Description)), userScope.CreatedAt.UTC(), createdBy,
		userScope.AllowExternalTemplateRepos, userScope.AllowCustomEveServers, userScope.AllowCustomNetlabServers, userScope.AllowCustomContainerlabServers, string(externalTemplateReposJSON),
		nullIfEmpty(strings.TrimSpace(userScope.Blueprint)), nullIfEmpty(strings.TrimSpace(userScope.DefaultBranch)),
		nullIfEmpty(strings.TrimSpace(userScope.TerraformStateKey)), userScope.TerraformInitTemplateID, userScope.TerraformPlanTemplateID, userScope.TerraformApplyTemplateID, userScope.AnsibleRunTemplateID, userScope.NetlabRunTemplateID, userScope.EveNgRunTemplateID, userScope.ContainerlabRunTemplateID,
		nullIfEmpty(strings.TrimSpace(userScope.AWSAccountID)), nullIfEmpty(strings.TrimSpace(userScope.AWSRoleName)), nullIfEmpty(strings.TrimSpace(userScope.AWSRegion)),
		nullIfEmpty(strings.TrimSpace(userScope.AWSAuthMethod)), nullIfEmpty(strings.TrimSpace(userScope.ArtifactsBucket)), userScope.IsPublic,
		nullIfEmpty(strings.TrimSpace(userScope.EveServer)), nullIfEmpty(strings.TrimSpace(userScope.NetlabServer)),
		strings.TrimSpace(userScope.GiteaOwner), strings.TrimSpace(userScope.GiteaRepo),
	); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM sf_user_scope_members WHERE user_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sf_user_scope_groups WHERE user_id=$1`, id); err != nil {
		return err
	}

	owners := normalizeUsernameList(userScope.Owners)
	ownerGroups := normalizeGroupList(userScope.OwnerGroups)
	editors := normalizeUsernameList(userScope.Editors)
	editorGroups := normalizeGroupList(userScope.EditorGroups)
	viewers := normalizeUsernameList(userScope.Viewers)
	viewerGroups := normalizeGroupList(userScope.ViewerGroups)
	if len(owners) == 0 && createdBy != "" {
		owners = []string{createdBy}
	}

	insertMember := func(username, role string) error {
		username = strings.ToLower(strings.TrimSpace(username))
		if username == "" || !isValidUsername(username) {
			return nil
		}
		_, err := tx.Exec(`INSERT INTO sf_user_scope_members (user_id, username, role) VALUES ($1,$2,$3)
ON CONFLICT (user_id, username) DO UPDATE SET role=excluded.role`, id, username, role)
		return err
	}
	for _, u := range owners {
		if err := insertMember(u, "owner"); err != nil {
			return err
		}
	}
	for _, u := range editors {
		if err := insertMember(u, "editor"); err != nil {
			return err
		}
	}
	for _, u := range viewers {
		if err := insertMember(u, "viewer"); err != nil {
			return err
		}
	}

	insertGroup := func(groupName, role string) error {
		groupName = strings.TrimSpace(groupName)
		if groupName == "" || len(groupName) > 512 {
			return nil
		}
		_, err := tx.Exec(`INSERT INTO sf_user_scope_groups (user_id, group_name, role) VALUES ($1,$2,$3)
ON CONFLICT (user_id, group_name) DO UPDATE SET role=excluded.role`, id, groupName, role)
		return err
	}
	for _, g := range ownerGroups {
		if err := insertGroup(g, "owner"); err != nil {
			return err
		}
	}
	for _, g := range editorGroups {
		if err := insertGroup(g, "editor"); err != nil {
			return err
		}
	}
	for _, g := range viewerGroups {
		if err := insertGroup(g, "viewer"); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *pgUserScopesStore) delete(userScopeID string) error {
	userScopeID = strings.TrimSpace(userScopeID)
	if userScopeID == "" {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext($1))`, userScopeID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sf_user_scopes WHERE id=$1`, userScopeID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *pgUserScopesStore) replaceAll(userScopes []UserScope) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('sf_user_scopes_replace_all'))`); err != nil {
		return err
	}

	ensureUser := func(username string) error {
		username = strings.ToLower(strings.TrimSpace(username))
		if username == "" || !isValidUsername(username) {
			return nil
		}
		_, err := tx.Exec(`INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, username)
		return err
	}

	for _, p := range userScopes {
		if err := ensureUser(p.CreatedBy); err != nil {
			return err
		}
		for _, u := range append(append([]string{}, p.Owners...), append(p.Editors, p.Viewers...)...) {
			if err := ensureUser(u); err != nil {
				return err
			}
		}
	}

	userScopeIDs := make([]string, 0, len(userScopes))
	for _, p := range userScopes {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			return fmt.Errorf("user scope id is required")
		}
		userScopeIDs = append(userScopeIDs, id)
		slug := strings.TrimSpace(p.Slug)
		if slug == "" {
			slug = slugify(p.Name)
		}
		createdBy := strings.ToLower(strings.TrimSpace(p.CreatedBy))
		if createdBy == "" {
			return fmt.Errorf("user-scope createdBy is required")
		}
		externalTemplateReposJSON, err := json.Marshal(p.ExternalTemplateRepos)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO sf_user_scopes (
			  id, slug, name, description, created_at, created_by,
			  allow_external_template_repos, allow_custom_eve_servers, allow_custom_netlab_servers, allow_custom_containerlab_servers, external_template_repos,
			  blueprint, default_branch, terraform_state_key, terraform_init_template_id, terraform_plan_template_id, terraform_apply_template_id, ansible_run_template_id, netlab_run_template_id, eve_ng_run_template_id, containerlab_run_template_id,
			  aws_account_id, aws_role_name, aws_region, aws_auth_method, artifacts_bucket, is_public,
			  eve_server, netlab_server, gitea_owner, gitea_repo, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,now())
			ON CONFLICT (id) DO UPDATE SET
			  slug=excluded.slug,
			  name=excluded.name,
			  description=excluded.description,
			  allow_external_template_repos=excluded.allow_external_template_repos,
			  allow_custom_eve_servers=excluded.allow_custom_eve_servers,
			  allow_custom_netlab_servers=excluded.allow_custom_netlab_servers,
			  allow_custom_containerlab_servers=excluded.allow_custom_containerlab_servers,
			  external_template_repos=excluded.external_template_repos,
			  blueprint=excluded.blueprint,
			  default_branch=excluded.default_branch,
			  terraform_state_key=excluded.terraform_state_key,
			  terraform_init_template_id=excluded.terraform_init_template_id,
			  terraform_plan_template_id=excluded.terraform_plan_template_id,
			  terraform_apply_template_id=excluded.terraform_apply_template_id,
			  ansible_run_template_id=excluded.ansible_run_template_id,
			  netlab_run_template_id=excluded.netlab_run_template_id,
			  eve_ng_run_template_id=excluded.eve_ng_run_template_id,
			  containerlab_run_template_id=excluded.containerlab_run_template_id,
			  aws_account_id=excluded.aws_account_id,
			  aws_role_name=excluded.aws_role_name,
			  aws_region=excluded.aws_region,
			  aws_auth_method=excluded.aws_auth_method,
			  artifacts_bucket=excluded.artifacts_bucket,
			  is_public=excluded.is_public,
			  eve_server=excluded.eve_server,
			  netlab_server=excluded.netlab_server,
			  gitea_owner=excluded.gitea_owner,
			  gitea_repo=excluded.gitea_repo,
			  updated_at=now()`,
			id, slug, strings.TrimSpace(p.Name), nullIfEmpty(strings.TrimSpace(p.Description)), p.CreatedAt.UTC(), createdBy,
			p.AllowExternalTemplateRepos, p.AllowCustomEveServers, p.AllowCustomNetlabServers, p.AllowCustomContainerlabServers, string(externalTemplateReposJSON),
			nullIfEmpty(strings.TrimSpace(p.Blueprint)), nullIfEmpty(strings.TrimSpace(p.DefaultBranch)),
			nullIfEmpty(strings.TrimSpace(p.TerraformStateKey)), p.TerraformInitTemplateID, p.TerraformPlanTemplateID, p.TerraformApplyTemplateID, p.AnsibleRunTemplateID, p.NetlabRunTemplateID, p.EveNgRunTemplateID, p.ContainerlabRunTemplateID,
			nullIfEmpty(strings.TrimSpace(p.AWSAccountID)), nullIfEmpty(strings.TrimSpace(p.AWSRoleName)), nullIfEmpty(strings.TrimSpace(p.AWSRegion)),
			nullIfEmpty(strings.TrimSpace(p.AWSAuthMethod)), nullIfEmpty(strings.TrimSpace(p.ArtifactsBucket)), p.IsPublic,
			nullIfEmpty(strings.TrimSpace(p.EveServer)), nullIfEmpty(strings.TrimSpace(p.NetlabServer)),
			strings.TrimSpace(p.GiteaOwner), strings.TrimSpace(p.GiteaRepo),
		); err != nil {
			return err
		}

		if _, err := tx.Exec(`DELETE FROM sf_user_scope_members WHERE user_id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM sf_user_scope_groups WHERE user_id=$1`, id); err != nil {
			return err
		}

		owners := normalizeUsernameList(p.Owners)
		ownerGroups := normalizeGroupList(p.OwnerGroups)
		editors := normalizeUsernameList(p.Editors)
		editorGroups := normalizeGroupList(p.EditorGroups)
		viewers := normalizeUsernameList(p.Viewers)
		viewerGroups := normalizeGroupList(p.ViewerGroups)
		if len(owners) == 0 && createdBy != "" {
			owners = []string{createdBy}
		}

		insertMember := func(username, role string) error {
			username = strings.ToLower(strings.TrimSpace(username))
			if username == "" || !isValidUsername(username) {
				return nil
			}
			_, err := tx.Exec(`INSERT INTO sf_user_scope_members (user_id, username, role) VALUES ($1,$2,$3)
ON CONFLICT (user_id, username) DO UPDATE SET role=excluded.role`, id, username, role)
			return err
		}
		for _, u := range owners {
			if err := insertMember(u, "owner"); err != nil {
				return err
			}
		}
		for _, u := range editors {
			if err := insertMember(u, "editor"); err != nil {
				return err
			}
		}
		for _, u := range viewers {
			if err := insertMember(u, "viewer"); err != nil {
				return err
			}
		}

		insertGroup := func(groupName, role string) error {
			groupName = strings.TrimSpace(groupName)
			if groupName == "" || len(groupName) > 512 {
				return nil
			}
			_, err := tx.Exec(`INSERT INTO sf_user_scope_groups (user_id, group_name, role) VALUES ($1,$2,$3)
ON CONFLICT (user_id, group_name) DO UPDATE SET role=excluded.role`, id, groupName, role)
			return err
		}
		for _, g := range ownerGroups {
			if err := insertGroup(g, "owner"); err != nil {
				return err
			}
		}
		for _, g := range editorGroups {
			if err := insertGroup(g, "editor"); err != nil {
				return err
			}
		}
		for _, g := range viewerGroups {
			if err := insertGroup(g, "viewer"); err != nil {
				return err
			}
		}
	}

	if len(userScopeIDs) == 0 {
		if _, err := tx.Exec(`DELETE FROM sf_user_scope_members`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM sf_user_scope_groups`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM sf_user_scopes`); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM sf_user_scopes WHERE NOT (id = ANY($1))`, userScopeIDs); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func openSkyforgeDB(ctx context.Context) (*sql.DB, error) {
	return skyforgedb.Open(ctx, skyforgeDB)
}

func slugify(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	var b strings.Builder
	b.Grow(len(s))
	lastDash := false
	for _, r := range s {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlnum {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' {
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "user"
	}
	return out
}

func parseUserList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "\n", ",")
	raw = strings.ReplaceAll(raw, "\t", ",")
	raw = strings.ReplaceAll(raw, " ", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(part)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, part)
	}
	return out
}

func isAdminUser(cfg Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	if strings.EqualFold(username, "admin") {
		return true
	}
	for _, u := range cfg.AdminUsers {
		if strings.EqualFold(u, username) {
			return true
		}
	}
	return false
}

func containsUser(list []string, username string) bool {
	for _, u := range list {
		if strings.EqualFold(u, username) {
			return true
		}
	}
	return false
}

func normalizeGroupList(groups []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > 512 {
			continue
		}
		key := strings.ToLower(g)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, g)
	}
	return out
}

func containsGroup(list []string, groups []string) bool {
	if len(list) == 0 || len(groups) == 0 {
		return false
	}
	owned := map[string]struct{}{}
	for _, g := range list {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		owned[g] = struct{}{}
	}
	for _, g := range groups {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		if _, ok := owned[g]; ok {
			return true
		}
	}
	return false
}

func normalizeUsernameList(list []string) []string {
	out := make([]string, 0, len(list))
	seen := map[string]bool{}
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !isValidUsername(item) {
			continue
		}
		key := strings.ToLower(item)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func isValidUsername(username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '@':
		default:
			return false
		}
	}
	return true
}

func userScopeAccessLevel(cfg Config, p UserScope, username string) string {
	if isAdminUser(cfg, username) {
		return "admin"
	}
	if containsUser(p.Owners, username) || strings.EqualFold(p.CreatedBy, username) {
		return "owner"
	}
	if containsUser(p.Editors, username) {
		return "editor"
	}
	if containsUser(p.Viewers, username) {
		return "viewer"
	}
	if p.IsPublic && !strings.EqualFold(strings.TrimSpace(p.CreatedBy), "skyforge") {
		return "viewer"
	}
	return "none"
}

func userScopeAccessLevelForClaims(cfg Config, p UserScope, claims *SessionClaims) string {
	if claims == nil {
		return "none"
	}
	if isAdminUser(cfg, claims.Username) {
		return "admin"
	}
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		return "none"
	}
	if strings.EqualFold(p.CreatedBy, username) || containsUser(p.Owners, username) || containsGroup(p.OwnerGroups, claims.Groups) {
		return "owner"
	}
	if containsUser(p.Editors, username) || containsGroup(p.EditorGroups, claims.Groups) {
		return "editor"
	}
	if containsUser(p.Viewers, username) || containsGroup(p.ViewerGroups, claims.Groups) {
		return "viewer"
	}
	if p.IsPublic && !strings.EqualFold(strings.TrimSpace(p.CreatedBy), "skyforge") {
		return "viewer"
	}
	return "none"
}

func syncGroupMembershipForUser(p *UserScope, claims *SessionClaims) (string, bool) {
	if p == nil || claims == nil {
		return "", false
	}
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		return "", false
	}
	if strings.EqualFold(p.CreatedBy, username) || containsUser(p.Owners, username) || containsUser(p.Editors, username) || containsUser(p.Viewers, username) {
		return "", false
	}
	if containsGroup(p.OwnerGroups, claims.Groups) {
		p.Owners = append(p.Owners, username)
		return "owner", true
	}
	if containsGroup(p.EditorGroups, claims.Groups) {
		p.Editors = append(p.Editors, username)
		return "editor", true
	}
	if containsGroup(p.ViewerGroups, claims.Groups) {
		p.Viewers = append(p.Viewers, username)
		return "viewer", true
	}
	return "", false
}

func findUserScopeByKey(userScopes []UserScope, key string) *UserScope {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	for i := range userScopes {
		if userScopes[i].ID == key || strings.EqualFold(userScopes[i].Slug, key) {
			return &userScopes[i]
		}
	}
	return nil
}

func syncGiteaCollaboratorsForUserScope(cfg Config, userScope UserScope) {
	owner := strings.TrimSpace(userScope.GiteaOwner)
	repo := strings.TrimSpace(userScope.GiteaRepo)
	if owner == "" || repo == "" {
		return
	}

	desired := map[string]string{}
	add := func(user, perm string) {
		user = strings.ToLower(strings.TrimSpace(user))
		if !isValidUsername(user) {
			return
		}
		if strings.EqualFold(user, cfg.UserScopes.GiteaUsername) {
			return
		}
		if existing, ok := desired[user]; ok {
			if existing == "admin" || perm == existing {
				return
			}
			if perm == "admin" {
				desired[user] = "admin"
				return
			}
			if existing == "write" && perm == "read" {
				return
			}
			if existing == "read" && perm == "write" {
				desired[user] = "write"
				return
			}
			return
		}
		desired[user] = perm
	}

	add(userScope.CreatedBy, "admin")
	for _, u := range userScope.Owners {
		add(u, "admin")
	}
	for _, u := range userScope.Editors {
		add(u, "write")
	}
	for _, u := range userScope.Viewers {
		add(u, "read")
	}

	for user, perm := range desired {
		if err := ensureGiteaCollaborator(cfg, owner, repo, user, perm); err != nil {
			log.Printf("gitea collaborator add (%s %s/%s): %v", user, owner, repo, err)
		}
	}

	current, err := listGiteaCollaborators(cfg, owner, repo)
	if err != nil {
		log.Printf("gitea collaborators list (%s/%s): %v", owner, repo, err)
		return
	}
	for _, user := range current {
		u := strings.ToLower(strings.TrimSpace(user))
		if u == "" || strings.EqualFold(u, cfg.UserScopes.GiteaUsername) {
			continue
		}
		if _, ok := desired[u]; ok {
			continue
		}
		if err := removeGiteaCollaborator(cfg, owner, repo, u); err != nil {
			log.Printf("gitea collaborator remove (%s %s/%s): %v", u, owner, repo, err)
		}
	}
}

type awsDeviceAuthSession struct {
	Username                string
	Region                  string
	StartURL                string
	DeviceCode              string
	IntervalSeconds         int32
	ExpiresAt               time.Time
	VerificationURIComplete string
	UserCode                string
}

// AWS device auth state is stored in Postgres to support multi-replica API deployments.

func awsAnonymousConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
}

func awsSSOClientKey(region string) string {
	return "__client__:" + strings.ToLower(strings.TrimSpace(region))
}

func ensureAWSOIDCClient(ctx context.Context, cfg Config, store awsSSOTokenStore) (string, string, time.Time, error) {
	region := strings.TrimSpace(cfg.AwsSSORegion)
	if region == "" {
		return "", "", time.Time{}, fmt.Errorf("AWS SSO is not configured (missing region)")
	}
	key := awsSSOClientKey(region)
	existing, err := store.get(key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if existing != nil && existing.ClientID != "" && existing.ClientSecret != "" && time.Now().Add(10*time.Minute).Before(existing.ClientSecretExpiresAt) {
		return existing.ClientID, existing.ClientSecret, existing.ClientSecretExpiresAt, nil
	}

	awsCfg, err := awsAnonymousConfig(ctx, region)
	if err != nil {
		return "", "", time.Time{}, err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	resp, err := oidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: ptr("skyforge"),
		ClientType: ptr("public"),
		Scopes:     []string{"sso:account:access"},
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt := time.Unix(int64(resp.ClientSecretExpiresAt), 0).UTC()
	record := awsSSOTokenRecord{
		StartURL:              strings.TrimSpace(cfg.AwsSSOStartURL),
		Region:                region,
		ClientID:              aws.ToString(resp.ClientId),
		ClientSecret:          aws.ToString(resp.ClientSecret),
		ClientSecretExpiresAt: expiresAt,
	}
	if err := store.put(key, record); err != nil {
		return "", "", time.Time{}, err
	}
	return record.ClientID, record.ClientSecret, record.ClientSecretExpiresAt, nil
}

func startAWSDeviceAuthorization(ctx context.Context, cfg Config, store awsSSOTokenStore, db *sql.DB, username string) (string, awsDeviceAuthSession, error) {
	startURL := strings.TrimSpace(cfg.AwsSSOStartURL)
	region := strings.TrimSpace(cfg.AwsSSORegion)
	if startURL == "" || region == "" {
		return "", awsDeviceAuthSession{}, fmt.Errorf("AWS SSO is not configured")
	}
	if db == nil {
		return "", awsDeviceAuthSession{}, fmt.Errorf("aws sso requires database")
	}
	clientID, clientSecret, _, err := ensureAWSOIDCClient(ctx, cfg, store)
	if err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	awsCfg, err := awsAnonymousConfig(ctx, region)
	if err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	resp, err := oidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     ptr(clientID),
		ClientSecret: ptr(clientSecret),
		StartUrl:     ptr(startURL),
	})
	if err != nil {
		return "", awsDeviceAuthSession{}, err
	}

	requestIDBytes := make([]byte, 18)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	requestID := base64.RawURLEncoding.EncodeToString(requestIDBytes)
	session := awsDeviceAuthSession{
		Username:                username,
		Region:                  region,
		StartURL:                startURL,
		DeviceCode:              aws.ToString(resp.DeviceCode),
		IntervalSeconds:         resp.Interval,
		ExpiresAt:               time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second).UTC(),
		VerificationURIComplete: aws.ToString(resp.VerificationUriComplete),
		UserCode:                aws.ToString(resp.UserCode),
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, strings.ToLower(strings.TrimSpace(username))); err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sf_aws_device_auth_requests (
  request_id, username, region, start_url, device_code, user_code, verification_uri_complete, interval_seconds, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		requestID,
		strings.ToLower(strings.TrimSpace(username)),
		strings.TrimSpace(region),
		strings.TrimSpace(startURL),
		strings.TrimSpace(session.DeviceCode),
		strings.TrimSpace(session.UserCode),
		strings.TrimSpace(session.VerificationURIComplete),
		int(session.IntervalSeconds),
		session.ExpiresAt.UTC(),
	); err != nil {
		_ = clientID
		_ = clientSecret
		return "", awsDeviceAuthSession{}, err
	}
	return requestID, session, nil
}

func pollAWSDeviceToken(ctx context.Context, cfg Config, store awsSSOTokenStore, db *sql.DB, requestID string) (*awsDeviceAuthSession, *ssooidc.CreateTokenOutput, string, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, nil, "not_found", nil
	}
	if db == nil {
		return nil, nil, "error", fmt.Errorf("aws sso requires database")
	}
	var session awsDeviceAuthSession
	var intervalSeconds int
	if err := db.QueryRowContext(ctx, `SELECT username, region, start_url, device_code, user_code, verification_uri_complete, interval_seconds, expires_at
FROM sf_aws_device_auth_requests WHERE request_id=$1`, requestID).Scan(
		&session.Username,
		&session.Region,
		&session.StartURL,
		&session.DeviceCode,
		&session.UserCode,
		&session.VerificationURIComplete,
		&intervalSeconds,
		&session.ExpiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, "not_found", nil
		}
		return nil, nil, "error", err
	}
	session.IntervalSeconds = int32(intervalSeconds)
	if time.Now().After(session.ExpiresAt) {
		_, _ = db.ExecContext(ctx, `DELETE FROM sf_aws_device_auth_requests WHERE request_id=$1`, requestID)
		return &session, nil, "expired", nil
	}

	clientID, clientSecret, _, err := ensureAWSOIDCClient(ctx, cfg, store)
	if err != nil {
		return &session, nil, "error", err
	}

	awsCfg, err := awsAnonymousConfig(ctx, session.Region)
	if err != nil {
		return &session, nil, "error", err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	out, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     ptr(clientID),
		ClientSecret: ptr(clientSecret),
		DeviceCode:   ptr(session.DeviceCode),
		GrantType:    ptr("urn:ietf:params:oauth:grant-type:device_code"),
	})
	if err != nil {
		var pending *ssooidcTypes.AuthorizationPendingException
		if errors.As(err, &pending) {
			return &session, nil, "pending", nil
		}
		var slow *ssooidcTypes.SlowDownException
		if errors.As(err, &slow) {
			return &session, nil, "pending", nil
		}
		var denied *ssooidcTypes.AccessDeniedException
		if errors.As(err, &denied) {
			_, _ = db.ExecContext(ctx, `DELETE FROM sf_aws_device_auth_requests WHERE request_id=$1`, requestID)
			return &session, nil, "denied", nil
		}
		var expired *ssooidcTypes.ExpiredTokenException
		if errors.As(err, &expired) {
			_, _ = db.ExecContext(ctx, `DELETE FROM sf_aws_device_auth_requests WHERE request_id=$1`, requestID)
			return &session, nil, "expired", nil
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM sf_aws_device_auth_requests WHERE request_id=$1`, requestID)
		return &session, nil, "error", err
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM sf_aws_device_auth_requests WHERE request_id=$1`, requestID)
	return &session, out, "ok", nil
}

func refreshAWSAccessToken(ctx context.Context, region, clientID, clientSecret, refreshToken string) (*ssooidc.CreateTokenOutput, error) {
	awsCfg, err := awsAnonymousConfig(ctx, region)
	if err != nil {
		return nil, err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	return oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     ptr(clientID),
		ClientSecret: ptr(clientSecret),
		RefreshToken: ptr(refreshToken),
		GrantType:    ptr("refresh_token"),
	})
}

func getAWSRoleCredentials(ctx context.Context, cfg Config, store awsSSOTokenStore, username, accountID, roleName string) (*sso.GetRoleCredentialsOutput, error) {
	accountID = strings.TrimSpace(accountID)
	roleName = strings.TrimSpace(roleName)
	if accountID == "" || roleName == "" {
		return nil, fmt.Errorf("missing aws environment id or role name")
	}
	if cfg.AwsSSOStartURL == "" || cfg.AwsSSORegion == "" {
		return nil, fmt.Errorf("AWS SSO is not configured")
	}

	record, err := store.get(username)
	if err != nil {
		return nil, err
	}
	if record == nil || record.RefreshToken == "" {
		return nil, fmt.Errorf("AWS SSO not connected")
	}

	clientID, clientSecret, _, err := ensureAWSOIDCClient(ctx, cfg, store)
	if err != nil {
		return nil, err
	}

	accessToken := record.AccessToken
	if accessToken == "" || time.Now().Add(2*time.Minute).After(record.AccessTokenExpiresAt) {
		refreshed, err := refreshAWSAccessToken(ctx, cfg.AwsSSORegion, clientID, clientSecret, record.RefreshToken)
		if err != nil {
			return nil, err
		}
		record.AccessToken = aws.ToString(refreshed.AccessToken)
		record.AccessTokenExpiresAt = time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second).UTC()
		if aws.ToString(refreshed.RefreshToken) != "" {
			record.RefreshToken = aws.ToString(refreshed.RefreshToken)
		}
		record.StartURL = strings.TrimSpace(cfg.AwsSSOStartURL)
		record.Region = strings.TrimSpace(cfg.AwsSSORegion)
		record.ClientID = clientID
		record.ClientSecret = clientSecret
		record.LastAuthenticatedAtUTC = time.Now().UTC()
		if err := store.put(username, *record); err != nil {
			return nil, err
		}
		accessToken = record.AccessToken
	}

	awsCfg, err := awsAnonymousConfig(ctx, cfg.AwsSSORegion)
	if err != nil {
		return nil, err
	}
	ssoClient := sso.NewFromConfig(awsCfg)
	return ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: ptr(accessToken),
		AccountId:   ptr(accountID),
		RoleName:    ptr(roleName),
	})
}

type userScopeSyncReport struct {
	UserScopeID string   `json:"userId"`
	Slug        string   `json:"slug"`
	Updated     bool     `json:"updated"`
	Steps       []string `json:"steps,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

func userScopeTerraformEnv(cfg Config, userScope UserScope) map[string]string {
	region := "us-east-1"
	if strings.TrimSpace(userScope.AWSRegion) != "" {
		region = strings.TrimSpace(userScope.AWSRegion)
	}
	env := map[string]string{
		"TF_IN_AUTOMATION":          "true",
		"TF_VAR_scenario":           "regular_cluster",
		"AWS_EC2_METADATA_DISABLED": "true",
		"AWS_REGION":                region,
		"TF_VAR_ssh_key_name":       "REPLACE_ME",
		"TF_VAR_artifacts_bucket":   "REPLACE_ME",
	}
	if cfg.UserScopes.ObjectStorageAccessKey != "" && cfg.UserScopes.ObjectStorageSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = cfg.UserScopes.ObjectStorageAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = cfg.UserScopes.ObjectStorageSecretKey
	}
	return env
}

func syncUserScopeResources(ctx context.Context, cfg Config, userScope *UserScope) userScopeSyncReport {
	report := userScopeSyncReport{
		UserScopeID: userScope.ID,
		Slug:        userScope.Slug,
	}
	addStep := func(msg string) {
		report.Steps = append(report.Steps, msg)
	}
	addErr := func(msg string, err error) {
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", msg, err))
		} else {
			report.Errors = append(report.Errors, msg)
		}
	}

	if strings.TrimSpace(userScope.GiteaOwner) == "" {
		userScope.GiteaOwner = strings.TrimSpace(cfg.UserScopes.GiteaUsername)
		report.Updated = true
		addStep("set gitea owner")
	}
	if strings.TrimSpace(userScope.GiteaRepo) == "" {
		userScope.GiteaRepo = strings.TrimSpace(userScope.Slug)
		report.Updated = true
		addStep("set gitea repo")
	}
	if strings.TrimSpace(userScope.ArtifactsBucket) != storage.StorageBucketName {
		userScope.ArtifactsBucket = storage.StorageBucketName
		report.Updated = true
		addStep("set artifacts bucket")
	}

	if strings.TrimSpace(userScope.GiteaOwner) != "" && strings.TrimSpace(userScope.GiteaRepo) != "" {
		repoPrivate := !userScope.IsPublic
		if err := ensureGiteaRepoFromBlueprint(cfg, userScope.GiteaOwner, userScope.GiteaRepo, userScope.Blueprint, repoPrivate); err != nil {
			addErr("gitea repo ensure", err)
		} else {
			addStep("gitea repo ok")
			if branch, err := getGiteaRepoDefaultBranch(cfg, userScope.GiteaOwner, userScope.GiteaRepo); err != nil {
				addErr("gitea default branch", err)
			} else if strings.TrimSpace(branch) != "" && branch != userScope.DefaultBranch {
				userScope.DefaultBranch = branch
				report.Updated = true
				addStep("updated default branch")
			}
		}
	}

	if strings.TrimSpace(userScope.GiteaOwner) != "" && strings.TrimSpace(userScope.GiteaRepo) != "" {
		syncGiteaCollaboratorsForUserScope(cfg, *userScope)
		addStep("gitea collaborators synced")
	}

	return report
}

func syncUserScopes(ctx context.Context, cfg Config, store userScopesStore, db *sql.DB) ([]userScopeSyncReport, error) {
	userScopes, err := store.load()
	if err != nil {
		return nil, err
	}
	reports := make([]userScopeSyncReport, 0, len(userScopes))
	changedWorkspaces := make([]UserScope, 0, 4)
	for i := range userScopes {
		userScopeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		report := syncUserScopeResources(userScopeCtx, cfg, &userScopes[i])
		cancel()
		if report.Updated {
			changedWorkspaces = append(changedWorkspaces, userScopes[i])
		}
		reports = append(reports, report)
	}
	for _, ws := range changedWorkspaces {
		if err := store.upsert(ws); err != nil {
			return reports, err
		}
	}
	if db != nil {
		for _, report := range reports {
			if !report.Updated {
				continue
			}
			details := fmt.Sprintf("updated=true errors=%d", len(report.Errors))
			auditCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			writeAuditEvent(auditCtx, db, "system", true, "", "user-scope.sync", report.UserScopeID, details)
			cancel()
		}
	}
	return reports, nil
}

type storageObjectSummary struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
}

func initService() (*Service, error) {
	meta := encore.Meta()
	rlog.Info("initializing skyforge service",
		"environment_name", meta.Environment.Name,
		"environment_type", meta.Environment.Type,
		"cloud", meta.Environment.Cloud,
		"app_id", meta.AppID,
	)

	sec := getSecrets()
	cfg := skyforgeconfig.LoadConfig(skyforgeEncoreCfg, sec)
	box := newSecretBox(cfg.SessionSecret)
	ldapPasswordBox = box
	var auth *LDAPAuthenticator
	if strings.TrimSpace(cfg.LDAP.URL) != "" && strings.TrimSpace(cfg.LDAP.BindTemplate) != "" {
		auth = NewLDAPAuthenticator(cfg.LDAP, cfg.MaxGroups)
	} else if strings.TrimSpace(cfg.LDAP.URL) != "" || strings.TrimSpace(cfg.LDAP.BindTemplate) != "" {
		log.Printf("LDAP config incomplete; LDAP auth disabled")
	} else {
		log.Printf("LDAP not configured; using local admin only")
	}
	sessionManager := NewSessionManager(cfg.SessionSecret, cfg.SessionCookie, cfg.SessionTTL, cfg.CookieSecure, cfg.CookieDomain)
	oidcClient, err := initOIDCClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("oidc init failed: %w", err)
	}
	var (
		userScopeStore userScopesStore
		awsStore       awsSSOTokenStore
		userStore      usersStore
		db             *sql.DB
	)

	db, err = openSkyforgeDB(context.Background())
	if err != nil {
		return nil, fmt.Errorf("postgres open failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres ping failed: %w", err)
	}

	pgWorkspaces := newPGUserScopesStore(db)
	pgUsers := newPGUsersStore(db)
	pgAWS := newPGAWSStore(db, box)

	userScopeStore = pgWorkspaces
	awsStore = pgAWS
	userStore = pgUsers

	// Background loops are scheduled externally (e.g. Kubernetes CronJobs) and enqueued for worker execution.

	svc := &Service{
		cfg:            cfg,
		auth:           auth,
		oidc:           oidcClient,
		sessionManager: sessionManager,
		userScopeStore: userScopeStore,
		awsStore:       awsStore,
		userStore:      userStore,
		box:            box,
		db:             db,
	}
	ensurePGNotifyHub(db)
	// Ensure the shared blueprint catalog exists for Gitea Explore even before any
	// user/user-scope bootstrap tasks run.
	if strings.TrimSpace(cfg.UserScopes.GiteaAPIURL) != "" && strings.TrimSpace(cfg.UserScopes.GiteaUsername) != "" {
		if err := ensureBlueprintCatalogRepo(cfg, defaultBlueprintCatalog); err != nil {
			rlog.Warn("ensureBlueprintCatalogRepo failed", "err", err)
		}
	}
	// Task worker heartbeats are emitted by the worker service (cron-driven).
	return svc, nil
}

// Session + Auth types

type UserProfile struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username"`
	DisplayName   string   `json:"displayName"`
	Email         string   `json:"email,omitempty"`
	Groups        []string `json:"groups"`
	IsAdmin       bool     `json:"isAdmin,omitempty"`
	ActorUsername string   `json:"actorUsername,omitempty"`
	Impersonating bool     `json:"impersonating,omitempty"`
}

type SessionResponse = UserProfile

type SessionClaims struct {
	Username         string   `json:"username"`
	DisplayName      string   `json:"displayName"`
	Email            string   `json:"email,omitempty"`
	Groups           []string `json:"groups"`
	ActorUsername    string   `json:"actorUsername,omitempty"`
	ActorDisplayName string   `json:"actorDisplayName,omitempty"`
	ActorEmail       string   `json:"actorEmail,omitempty"`
	ActorGroups      []string `json:"actorGroups,omitempty"`
	jwt.RegisteredClaims
}

type SessionManager struct {
	secret       []byte
	cookieName   string
	ttl          time.Duration
	secureMode   string
	cookieDomain string
}

//encore:service
type Service struct {
	cfg            Config
	auth           *LDAPAuthenticator
	oidc           *OIDCClient
	sessionManager *SessionManager
	userScopeStore userScopesStore
	awsStore       awsSSOTokenStore
	userStore      usersStore
	box            *secretBox
	db             *sql.DB
}

func NewSessionManager(secret, cookie string, ttl time.Duration, secureMode, cookieDomain string) *SessionManager {
	return &SessionManager{
		secret:       []byte(secret),
		cookieName:   cookie,
		ttl:          ttl,
		secureMode:   strings.TrimSpace(strings.ToLower(secureMode)),
		cookieDomain: strings.TrimSpace(cookieDomain),
	}
}

func (sm *SessionManager) Issue(w http.ResponseWriter, r *http.Request, profile *UserProfile) error {
	cookie, err := sm.issueCookie(profile, nil, sm.cookieSecure(r))
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

func (sm *SessionManager) IssueImpersonated(w http.ResponseWriter, r *http.Request, actor *SessionClaims, profile *UserProfile) error {
	cookie, err := sm.issueCookie(profile, actor, sm.cookieSecure(r))
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

func (sm *SessionManager) cookieSecure(r *http.Request) bool {
	switch sm.secureMode {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		if r != nil && r.TLS != nil {
			return true
		}
		if r != nil && sm.cookieSecureFromHeaders(r.Header) {
			return true
		}
		return false
	}
}

func (sm *SessionManager) IssueCookieForHeaders(headers http.Header, profile *UserProfile) (*http.Cookie, error) {
	return sm.issueCookie(profile, nil, sm.cookieSecureFromHeaders(headers))
}

func (sm *SessionManager) IssueImpersonatedCookieForHeaders(headers http.Header, actor *SessionClaims, profile *UserProfile) (*http.Cookie, error) {
	return sm.issueCookie(profile, actor, sm.cookieSecureFromHeaders(headers))
}

func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, sm.ClearCookie())
}

func (sm *SessionManager) ClearCookie() *http.Cookie {
	cookie := &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	if sm.cookieDomain != "" {
		cookie.Domain = sm.cookieDomain
	}
	return cookie
}

func (sm *SessionManager) issueCookie(profile *UserProfile, actor *SessionClaims, secure bool) (*http.Cookie, error) {
	now := time.Now()
	expires := now.Add(sm.ttl)
	// Canonicalize usernames to lowercase for all persisted/session state.
	// This keeps DB lookups consistent (sf_users and related FK tables) and avoids
	// case-related mismatches across IdPs.
	username := strings.ToLower(strings.TrimSpace(profile.Username))
	claims := SessionClaims{
		Username:    username,
		DisplayName: profile.DisplayName,
		Email:       profile.Email,
		Groups:      profile.Groups,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}
	if actor != nil {
		claims.ActorUsername = strings.ToLower(strings.TrimSpace(actor.Username))
		claims.ActorDisplayName = strings.TrimSpace(actor.DisplayName)
		claims.ActorEmail = strings.TrimSpace(actor.Email)
		claims.ActorGroups = actor.Groups
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sm.secret)
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{
		Name:     sm.cookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
	if sm.cookieDomain != "" {
		cookie.Domain = sm.cookieDomain
	}
	return cookie, nil
}

func (sm *SessionManager) cookieSecureFromHeaders(headers http.Header) bool {
	switch sm.secureMode {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		if headers == nil {
			return false
		}
		xfp := headers.Get("X-Forwarded-Proto")
		return strings.Contains(strings.ToLower(xfp), "https")
	}
}

func (sm *SessionManager) Parse(r *http.Request) (*SessionClaims, error) {
	cookie, err := r.Cookie(sm.cookieName)
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseWithClaims(cookie.Value, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return sm.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*SessionClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid session")
}

func adminUsernameForClaims(claims *SessionClaims) string {
	if claims == nil {
		return ""
	}
	if strings.TrimSpace(claims.ActorUsername) != "" {
		return strings.TrimSpace(claims.ActorUsername)
	}
	return strings.TrimSpace(claims.Username)
}

func isAdminForClaims(cfg Config, claims *SessionClaims) bool {
	if claims == nil {
		return false
	}

	candidates := []string{
		strings.TrimSpace(claims.Username),
		strings.TrimSpace(claims.Email),
		strings.TrimSpace(claims.ActorUsername),
		strings.TrimSpace(claims.ActorEmail),
	}
	for _, c := range candidates {
		if isAdminUser(cfg, c) {
			return true
		}
	}
	return false
}

func isImpersonating(claims *SessionClaims) bool {
	if claims == nil {
		return false
	}
	if strings.TrimSpace(claims.ActorUsername) == "" {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(claims.ActorUsername), strings.TrimSpace(claims.Username))
}

func auditActor(cfg Config, claims *SessionClaims) (actor string, actorIsAdmin bool, impersonated string) {
	actor = adminUsernameForClaims(claims)
	actorIsAdmin = isAdminForClaims(cfg, claims)
	if isImpersonating(claims) {
		impersonated = strings.TrimSpace(claims.Username)
	}
	return actor, actorIsAdmin, impersonated
}

type staticHandler struct {
	brandDir string
	docsDir  string
}

func newStaticHandler(staticRoot string) *staticHandler {
	root := strings.TrimSpace(staticRoot)
	if root == "" {
		root = "/opt/skyforge/static"
	}
	return &staticHandler{
		brandDir: filepath.Join(root, "brand"),
		docsDir:  filepath.Join(root, "docs"),
	}
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	w.Header().Set("Cache-Control", "no-store")

	switch {
	case strings.HasPrefix(path, "/brand/"):
		http.StripPrefix("/brand/", http.FileServer(http.Dir(h.brandDir))).ServeHTTP(w, r)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (sm *SessionManager) Require(handler func(http.ResponseWriter, *http.Request, *SessionClaims)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := sm.Parse(r)
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		handler(w, r, claims)
	})
}

// LDAP authentication

type LDAPAuthenticator struct {
	cfg       LDAPConfig
	maxGroups int
}

func NewLDAPAuthenticator(cfg LDAPConfig, maxGroups int) *LDAPAuthenticator {
	if maxGroups <= 0 {
		maxGroups = 50
	}
	return &LDAPAuthenticator{cfg: cfg, maxGroups: maxGroups}
}

type AuthFailure struct {
	Status        int
	PublicMessage string
	Err           error
}

func (a *AuthFailure) Error() string {
	if a == nil {
		return ""
	}
	if a.Err != nil {
		return a.Err.Error()
	}
	return a.PublicMessage
}

func (a *AuthFailure) Unwrap() error {
	if a == nil {
		return nil
	}
	return a.Err
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserProfile, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, &AuthFailure{Status: http.StatusUnauthorized, PublicMessage: "missing credentials", Err: errors.New("missing credentials")}
	}

	conn, err := dialLDAP(a.cfg)
	if err != nil {
		return nil, classifyLDAPError(err)
	}
	defer conn.Close()

	if err := startTLSSafely(conn, a.cfg); err != nil {
		return nil, classifyLDAPError(err)
	}

	userDN := fmt.Sprintf(a.cfg.BindTemplate, ldap.EscapeDN(username))
	if err := conn.Bind(userDN, password); err != nil {
		return nil, classifyLDAPError(err)
	}

	attrs := []string{a.cfg.DisplayNameAttr, a.cfg.MailAttr, a.cfg.GroupAttr}
	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attrs,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, classifyLDAPError(err)
	}
	if len(sr.Entries) == 0 {
		return nil, &AuthFailure{Status: http.StatusUnauthorized, PublicMessage: "user not found", Err: errors.New("user entry not found")}
	}
	entry := sr.Entries[0]
	display := entry.GetAttributeValue(a.cfg.DisplayNameAttr)
	if display == "" {
		display = username
	}
	email := entry.GetAttributeValue(a.cfg.MailAttr)
	groups := entry.GetAttributeValues(a.cfg.GroupAttr)
	// Normalize group names to simple values when memberOf returns full DN
	for i, g := range groups {
		if strings.Contains(g, ",") {
			parts := strings.SplitN(g, ",", 2)
			if strings.HasPrefix(strings.ToLower(parts[0]), "cn=") {
				groups[i] = strings.TrimPrefix(parts[0], "cn=")
			}
		}
	}

	if len(groups) > 0 {
		seen := make(map[string]struct{}, len(groups))
		unique := make([]string, 0, len(groups))
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}
			unique = append(unique, g)
		}
		groups = unique
		if a.maxGroups > 0 && len(groups) > a.maxGroups {
			groups = groups[:a.maxGroups]
		}
	}

	return &UserProfile{
		Authenticated: true,
		Username:      username,
		DisplayName:   display,
		Email:         email,
		Groups:        groups,
	}, nil
}

func lookupLDAPUserProfile(ctx context.Context, cfg LDAPConfig, username string, maxGroups int, bindDN string, bindPassword string) (*UserProfile, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("missing username")
	}
	if maxGroups <= 0 {
		maxGroups = 50
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := startTLSSafely(conn, cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(bindDN) != "" {
		if err := conn.Bind(strings.TrimSpace(bindDN), bindPassword); err != nil {
			return nil, err
		}
	}

	userDN := fmt.Sprintf(cfg.BindTemplate, ldap.EscapeDN(username))
	attrs := []string{cfg.DisplayNameAttr, cfg.MailAttr, cfg.GroupAttr}
	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attrs,
		nil,
	)
	_ = ctx
	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, errors.New("user not found")
	}
	entry := sr.Entries[0]
	display := entry.GetAttributeValue(cfg.DisplayNameAttr)
	if display == "" {
		display = username
	}
	email := entry.GetAttributeValue(cfg.MailAttr)
	groups := entry.GetAttributeValues(cfg.GroupAttr)
	for i, g := range groups {
		if strings.Contains(g, ",") {
			parts := strings.SplitN(g, ",", 2)
			if strings.HasPrefix(strings.ToLower(parts[0]), "cn=") {
				groups[i] = strings.TrimPrefix(parts[0], "cn=")
			}
		}
	}
	if len(groups) > 0 {
		seen := make(map[string]struct{}, len(groups))
		unique := make([]string, 0, len(groups))
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			key := strings.ToLower(g)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			unique = append(unique, g)
		}
		groups = unique
		if maxGroups > 0 && len(groups) > maxGroups {
			groups = groups[:maxGroups]
		}
	}
	return &UserProfile{
		Authenticated: true,
		Username:      username,
		DisplayName:   display,
		Email:         email,
		Groups:        groups,
	}, nil
}

func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(parsed.Scheme, "ldaps") {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
		if host := parsed.Hostname(); host != "" && tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	return ldap.DialURL(cfg.URL, opts...)
}

func startTLSSafely(conn *ldap.Conn, cfg LDAPConfig) error {
	if !cfg.UseStartTLS {
		return nil
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}
	if strings.EqualFold(parsed.Scheme, "ldaps") {
		return nil
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
	if host := parsed.Hostname(); host != "" && tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}
	return conn.StartTLS(tlsCfg)
}

func classifyLDAPError(err error) error {
	if err == nil {
		return nil
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return &AuthFailure{Status: http.StatusUnauthorized, PublicMessage: "invalid credentials", Err: err}
		case ldap.LDAPResultConfidentialityRequired, ldap.LDAPResultStrongAuthRequired:
			return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "LDAP requires TLS (StartTLS/LDAPS)", Err: err}
		default:
			if ldapErr.ResultCode == ldap.ErrorNetwork {
				return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "unable to reach LDAP server", Err: err}
			}
			return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "LDAP authentication error", Err: err}
		}
	}
	return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "authentication backend error", Err: err}
}

func checkLDAPConnectivity(ctx context.Context, cfg LDAPConfig) error {
	// Best-effort connectivity check: dial + optional StartTLS handshake; no bind.
	conn, err := dialLDAP(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = ctx
	if err := startTLSSafely(conn, cfg); err != nil {
		return err
	}
	return nil
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}

func extractLabIDFromMetadataPath(stateRoot, path string) string {
	stateRoot = strings.TrimSuffix(stateRoot, "/")
	if stateRoot != "" && strings.HasPrefix(path, stateRoot+"/") {
		rest := strings.TrimPrefix(path, stateRoot+"/")
		parts := strings.Split(rest, "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	parts := strings.Split(strings.TrimSuffix(path, "/metadata.json"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func getSetting(ctx context.Context, db *sql.DB, key string) (string, bool, error) {
	if db == nil {
		return "", false, nil
	}
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM sf_settings WHERE key=$1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return value, true, nil
}

func upsertSetting(ctx context.Context, db *sql.DB, key, value string) error {
	if db == nil {
		return fmt.Errorf("settings store unavailable")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_settings (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, key, value)
	return err
}

func notificationSettings(ctx context.Context, db *sql.DB, cfg Config) (NotificationSettings, error) {
	interval := cfg.NotificationsInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	settings := NotificationSettings{
		PollingEnabled:    cfg.NotificationsEnabled,
		PollingIntervalMs: interval.Milliseconds(),
	}
	if db == nil {
		return settings, nil
	}
	if value, ok, err := getSetting(ctx, db, "notifications_polling_enabled"); err != nil {
		return settings, err
	} else if ok {
		if parsed, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil {
			settings.PollingEnabled = parsed
		}
	}
	if value, ok, err := getSetting(ctx, db, "notifications_polling_interval"); err != nil {
		return settings, err
	} else if ok {
		if parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && parsed > 0 {
			settings.PollingIntervalMs = parsed
		}
	}
	return settings, nil
}

func listNotifications(ctx context.Context, db *sql.DB, username string, includeRead bool, limit int) ([]NotificationRecord, error) {
	if db == nil {
		return []NotificationRecord{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 25
	}
	query := `SELECT id, username, title, message, type, category, reference_id, priority, is_read, created_at, updated_at
FROM sf_notifications
WHERE username=$1`
	if !includeRead {
		query += " AND is_read=false"
	}
	query += " ORDER BY created_at DESC LIMIT $2"

	rows, err := db.QueryContext(ctx, query, strings.ToLower(strings.TrimSpace(username)), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationRecord{}
	for rows.Next() {
		var rec NotificationRecord
		if err := rows.Scan(
			&rec.ID,
			&rec.Username,
			&rec.Title,
			&rec.Message,
			&rec.Type,
			&rec.Category,
			&rec.ReferenceID,
			&rec.Priority,
			&rec.IsRead,
			&rec.CreatedAt,
			&rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func markNotificationRead(ctx context.Context, db *sql.DB, username, id string) error {
	if db == nil {
		return nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	res, err := db.ExecContext(ctx, `UPDATE sf_notifications SET is_read=true, updated_at=now() WHERE id=$1 AND username=$2`, id, username)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	_ = notifyNotificationUpdatePG(ctx, db, username)
	return nil
}

func markAllNotificationsRead(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	_, err := db.ExecContext(ctx, `UPDATE sf_notifications SET is_read=true, updated_at=now() WHERE username=$1 AND is_read=false`, username)
	if err == nil {
		_ = notifyNotificationUpdatePG(ctx, db, username)
	}
	return err
}

func deleteNotification(ctx context.Context, db *sql.DB, username, id string) error {
	if db == nil {
		return nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	res, err := db.ExecContext(ctx, `DELETE FROM sf_notifications WHERE id=$1 AND username=$2`, id, username)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	_ = notifyNotificationUpdatePG(ctx, db, username)
	return nil
}

func createNotification(ctx context.Context, db *sql.DB, username, title, message, typ, category, referenceID, priority string) (string, error) {
	if db == nil {
		return "", nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Notification"
	}
	if typ == "" {
		typ = "SYSTEM"
	}
	if priority == "" {
		priority = "low"
	}
	ensureAuditActor(ctx, db, username)
	id := uuid.NewString()
	_, err := db.ExecContext(ctx, `INSERT INTO sf_notifications (
	  id, username, title, message, type, category, reference_id, priority
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, username, title, strings.TrimSpace(message), strings.TrimSpace(typ), nullIfEmpty(strings.TrimSpace(category)), nullIfEmpty(strings.TrimSpace(referenceID)), nullIfEmpty(strings.TrimSpace(priority)))
	if err != nil {
		return "", err
	}
	_ = notifyNotificationUpdatePG(ctx, db, username)
	return id, nil
}

func shouldNotifyCloudCredential(ctx context.Context, db *sql.DB, key string, ok bool) bool {
	if db == nil {
		return !ok
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return !ok
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctxReq, nil)
	if err != nil {
		return !ok
	}
	defer func() { _ = tx.Rollback() }()

	var prev bool
	err = tx.QueryRowContext(ctxReq, `SELECT ok FROM sf_cloud_credential_status WHERE key=$1 FOR UPDATE`, key).Scan(&prev)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctxReq, `INSERT INTO sf_cloud_credential_status (key, ok, updated_at) VALUES ($1,$2,now())`, key, ok); err != nil {
				return !ok
			}
			if err := tx.Commit(); err != nil {
				return !ok
			}
			return !ok
		}
		return !ok
	}
	if _, err := tx.ExecContext(ctxReq, `UPDATE sf_cloud_credential_status SET ok=$2, updated_at=now() WHERE key=$1`, key, ok); err != nil {
		return !ok
	}
	if err := tx.Commit(); err != nil {
		return !ok
	}
	return prev && !ok
}

func userScopeNotificationRecipients(userScope UserScope) []string {
	recipients := map[string]struct{}{}
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		recipients[value] = struct{}{}
	}
	add(userScope.CreatedBy)
	for _, owner := range userScope.Owners {
		add(owner)
	}
	out := make([]string, 0, len(recipients))
	for owner := range recipients {
		out = append(out, owner)
	}
	sort.Strings(out)
	return out
}

func validateAWSStaticCredentials(ctx context.Context, region string, creds *awsStaticCredentials) error {
	region = strings.TrimSpace(region)
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)),
	)
	if err != nil {
		return err
	}
	client := sts.NewFromConfig(cfg)
	_, err = client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}

// helpers

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lrw.status, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if raw, ok := obj[key]; ok {
			if val, ok := raw.(string); ok && strings.TrimSpace(val) != "" {
				return strings.TrimSpace(val)
			}
			if val, ok := raw.(json.Number); ok {
				return val.String()
			}
		}
	}
	return ""
}

func parseActorFromMessage(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	lastOpen := strings.LastIndex(message, "(")
	lastClose := strings.LastIndex(message, ")")
	if lastOpen == -1 || lastClose == -1 || lastClose < lastOpen {
		return ""
	}
	if strings.TrimSpace(message[lastClose+1:]) != "" {
		return ""
	}
	candidate := strings.TrimSpace(message[lastOpen+1 : lastClose])
	if candidate == "" {
		return ""
	}
	for _, r := range candidate {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return ""
	}
	return candidate
}

func listNetlabLabs(ctx context.Context, cfg Config, netlabCfg NetlabConfig, owner string, mode string) ([]LabSummary, map[string]any, error) {
	source := map[string]any{
		"provider":  "netlab",
		"mode":      "live",
		"transport": "ssh",
		"endpoint":  "ssh:" + netlabCfg.SSHHost,
	}

	if netlabCfg.SSHHost == "" || netlabCfg.SSHKeyFile == "" {
		source["mode"] = "disabled"
		return []LabSummary{}, source, fmt.Errorf("netlab runner is not configured")
	}

	client, err := dialSSH(netlabCfg)
	if err != nil {
		return []LabSummary{}, source, err
	}
	defer client.Close()

	limit := 50
	cmd := fmt.Sprintf("find %q -maxdepth 2 -type f -name metadata.json 2>/dev/null | head -n %d", netlabCfg.StateRoot, limit)
	out, err := runSSHCommand(client, cmd, 10*time.Second)
	if err != nil {
		return []LabSummary{}, source, err
	}
	paths := strings.Fields(out)

	labs := make([]LabSummary, 0, len(paths))
	now := time.Now().UTC().Format(time.RFC3339)
	for _, p := range paths {
		content, err := runSSHCommand(client, fmt.Sprintf("cat %q", p), 10*time.Second)
		if err != nil {
			continue
		}
		var meta map[string]any
		if err := json.Unmarshal([]byte(content), &meta); err != nil {
			continue
		}
		labID := extractLabIDFromMetadataPath(netlabCfg.StateRoot, p)
		name := firstString(meta, "name", "lab", "title", "scenario")
		if name == "" {
			name = labID
		}
		labOwner := firstString(meta, "owner", "user", "username", "created_by")
		status := strings.ToLower(firstString(meta, "status", "state"))
		if status == "" {
			status = "running"
		}
		labs = append(labs, LabSummary{
			ID:        "netlab:" + labID,
			Name:      name,
			Owner:     labOwner,
			Status:    status,
			Provider:  "netlab",
			UpdatedAt: firstString(meta, "updated_at", "updatedAt", "timestamp"),
		})
		if labs[len(labs)-1].UpdatedAt == "" {
			labs[len(labs)-1].UpdatedAt = now
		}
	}

	if owner != "" {
		filtered := make([]LabSummary, 0, len(labs))
		for _, lab := range labs {
			if lab.Owner == "" {
				continue
			}
			if strings.EqualFold(lab.Owner, owner) {
				filtered = append(filtered, lab)
			}
		}
		labs = filtered
	}

	if mode == "running" {
		running := make([]LabSummary, 0, len(labs))
		for _, lab := range labs {
			if lab.Status == "running" {
				running = append(running, lab)
			}
		}
		labs = running
	}

	return labs, source, nil
}

func parseSkyforgeMarkers(output []map[string]any) (map[string]string, map[string]string) {
	labs := map[string]string{}
	artifacts := map[string]string{}
	for _, row := range output {
		out, _ := row["output"].(string)
		if out == "" {
			continue
		}
		line := strings.TrimSpace(out)
		if strings.Contains(line, "SKYFORGE_OUTPUT ") {
			parts := strings.SplitN(line, "SKYFORGE_OUTPUT ", 2)
			if len(parts) == 2 {
				kv := strings.TrimSpace(parts[1])
				key, val, ok := strings.Cut(kv, "=")
				if ok {
					key = strings.TrimSpace(key)
					val = strings.TrimSpace(val)
					if key != "" && val != "" {
						labs[key] = val
					}
				}
			}
		}
		if strings.Contains(line, "SKYFORGE_ARTIFACT ") {
			parts := strings.SplitN(line, "SKYFORGE_ARTIFACT ", 2)
			if len(parts) == 2 {
				kv := strings.TrimSpace(parts[1])
				key, val, ok := strings.Cut(kv, "=")
				if ok {
					key = strings.TrimSpace(key)
					val = strings.TrimSpace(val)
					if key != "" && val != "" {
						artifacts[key] = val
					}
				}
			}
		}
	}
	return labs, artifacts
}

func firstNumber(obj map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if raw, ok := obj[key]; ok {
			switch v := raw.(type) {
			case float64:
				return v
			case int:
				return float64(v)
			case int64:
				return float64(v)
			case json.Number:
				if f, err := v.Float64(); err == nil {
					return f
				}
			}
		}
	}
	return 0
}
