package maintenancejobs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"encore.app/integrations/gitea"
	"encore.app/internal/pglocks"
	"encore.app/internal/secretbox"
	"encore.app/internal/skyforgecore"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
)

const (
	lockUserSync             int64 = 74004
	lockCloudCredentialCheck int64 = 74005

	pgNotifyNotificationsChannel = "skyforge_notification_updates"
)

func Run(ctx context.Context, cfg skyforgecore.Config, db *sql.DB, kind string) error {
	kind = strings.TrimSpace(kind)
	if kind == "" || db == nil {
		return nil
	}
	switch kind {
	case "user_sync":
		return withAdvisoryLock(ctx, db, lockUserSync, func(ctx context.Context) error {
			return runUserContextSync(ctx, cfg, db)
		})
	case "cloud_credential_checks":
		return withAdvisoryLock(ctx, db, lockCloudCredentialCheck, func(ctx context.Context) error {
			return runCloudCredentialChecks(ctx, cfg, db)
		})
	default:
		return nil
	}
}

func withAdvisoryLock(ctx context.Context, db *sql.DB, key int64, fn func(context.Context) error) error {
	if fn == nil || db == nil {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	lock, locked, err := pglocks.TryAdvisoryLock(ctxReq, db, key)
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer func() {
		ctxUnlock, cancelUnlock := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelUnlock()
		_ = lock.Unlock(ctxUnlock)
	}()
	return fn(ctx)
}

type scopeRecord struct {
	ID              string
	Slug            string
	Name            string
	CreatedBy       string
	IsPublic        bool
	DefaultBranch   string
	ArtifactsBucket string
	GiteaOwner      string
	GiteaRepo       string

	Owners  []string
	Editors []string
	Viewers []string

	// Cloud config fields
	AWSAuthMethod string
	AWSRegion     string
}

func runUserContextSync(ctx context.Context, cfg skyforgecore.Config, db *sql.DB) error {
	scopes, err := loadUsersForMaintenance(ctx, db)
	if err != nil {
		return err
	}
	client := gitea.New(gitea.Config{
		APIURL:       strings.TrimSpace(cfg.Scopes.GiteaAPIURL),
		Username:     strings.TrimSpace(cfg.Scopes.GiteaUsername),
		Password:     strings.TrimSpace(cfg.Scopes.GiteaPassword),
		RepoPrivate:  cfg.Scopes.GiteaRepoPrivate,
		DefaultEmail: strings.TrimSpace(cfg.Scopes.GiteaUsername) + "@example.invalid",
	})

	for _, ws := range scopes {
		updated := false

		desiredOwner := strings.TrimSpace(ws.GiteaOwner)
		if desiredOwner == "" {
			desiredOwner = strings.TrimSpace(cfg.Scopes.GiteaUsername)
		}
		desiredRepo := strings.TrimSpace(ws.GiteaRepo)
		if desiredRepo == "" {
			desiredRepo = strings.TrimSpace(ws.Slug)
		}
		desiredBucket := strings.TrimSpace(ws.ArtifactsBucket)
		if desiredBucket == "" {
			desiredBucket = "skyforge"
		}

		if desiredOwner != ws.GiteaOwner || desiredRepo != ws.GiteaRepo || desiredBucket != ws.ArtifactsBucket {
			ws.GiteaOwner = desiredOwner
			ws.GiteaRepo = desiredRepo
			ws.ArtifactsBucket = desiredBucket
			updated = true
		}

		if ws.GiteaOwner != "" && ws.GiteaRepo != "" {
			repoPrivate := !ws.IsPublic
			if err := client.EnsureRepo(ws.GiteaOwner, ws.GiteaRepo); err == nil {
				_ = client.SetRepoPrivate(ws.GiteaOwner, ws.GiteaRepo, repoPrivate)
				if branch, err := client.GetRepoDefaultBranch(ws.GiteaOwner, ws.GiteaRepo); err == nil && strings.TrimSpace(branch) != "" && strings.TrimSpace(branch) != ws.DefaultBranch {
					ws.DefaultBranch = strings.TrimSpace(branch)
					updated = true
				}
			}
			syncGiteaCollaborators(client, cfg, ws)
		}

		if updated {
			if err := updateUserMaintenanceFields(ctx, db, ws); err != nil {
				return err
			}
			writeAuditEvent(ctx, db, "system", true, "", "user.sync", ws.ID, "updated=true")
		}
	}

	return nil
}

func runCloudCredentialChecks(ctx context.Context, cfg skyforgecore.Config, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	now := time.Now().UTC()
	if tokens, err := loadAwsSSOTokens(ctx, db); err == nil {
		for username, rec := range tokens {
			username = strings.ToLower(strings.TrimSpace(username))
			if username == "" {
				continue
			}
			if strings.TrimSpace(rec.RefreshToken) == "" {
				continue
			}
			if !rec.RefreshTokenExpiresAt.IsZero() && now.After(rec.RefreshTokenExpiresAt) {
				if shouldNotifyCloudCredential(ctx, db, "aws-sso:"+username, false) {
					_, _ = createNotification(ctx, db, username, "AWS SSO session expired",
						"Your AWS SSO session expired. Re-authenticate in Settings.",
						"warning", "cloud-credentials", "/dashboard/settings", "high")
				}
			} else {
				shouldNotifyCloudCredential(ctx, db, "aws-sso:"+username, true)
			}
		}
	}

	scopes, err := loadUsersForMaintenance(ctx, db)
	if err != nil {
		return nil
	}
	box := secretbox.New(cfg.SessionSecret)
	for _, ws := range scopes {
		recipients := scopeNotificationRecipients(ws)
		if len(recipients) == 0 {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(ws.AWSAuthMethod), "static") {
			creds, err := getUserAWSStaticCredentials(ctx, db, box, ws.ID)
			key := "aws-static:" + ws.ID
			if err != nil || creds == nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
				if shouldNotifyCloudCredential(ctx, db, key, false) {
					for _, username := range recipients {
						_, _ = createNotification(ctx, db, username, "AWS static credentials missing",
							fmt.Sprintf("Scope %s is missing AWS static credentials. Update them in Settings.", ws.Name),
							"warning", "cloud-credentials", "/dashboard/settings", "high")
					}
				}
			} else {
				validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				validateErr := validateAWSStaticCredentials(validateCtx, ws.AWSRegion, creds)
				cancel()
				if validateErr != nil {
					if shouldNotifyCloudCredential(ctx, db, key, false) {
						for _, username := range recipients {
							_, _ = createNotification(ctx, db, username, "AWS static credentials invalid",
								fmt.Sprintf("Scope %s failed AWS static validation. Re-enter credentials in Settings.", ws.Name),
								"warning", "cloud-credentials", "/dashboard/settings", "high")
						}
					}
				} else {
					shouldNotifyCloudCredential(ctx, db, key, true)
				}
			}
		}

		azureCreds, err := getUserAzureCredentials(ctx, db, box, ws.ID)
		if azureCreds != nil {
			key := "azure:" + ws.ID
			if err != nil || azureCreds.ClientID == "" || azureCreds.ClientSecret == "" {
				if shouldNotifyCloudCredential(ctx, db, key, false) {
					for _, username := range recipients {
						_, _ = createNotification(ctx, db, username, "Azure credentials missing",
							fmt.Sprintf("Scope %s is missing Azure credentials. Re-enter them in Settings.", ws.Name),
							"warning", "cloud-credentials", "/dashboard/settings", "high")
					}
				}
			} else {
				validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, tokenErr := fetchAzureToken(validateCtx, azureCreds.TenantID, azureCreds.ClientID, azureCreds.ClientSecret)
				cancel()
				if tokenErr != nil {
					if shouldNotifyCloudCredential(ctx, db, key, false) {
						for _, username := range recipients {
							_, _ = createNotification(ctx, db, username, "Azure credentials invalid",
								fmt.Sprintf("Scope %s failed Azure validation. Re-enter credentials in Settings.", ws.Name),
								"warning", "cloud-credentials", "/dashboard/settings", "high")
						}
					}
				} else {
					shouldNotifyCloudCredential(ctx, db, key, true)
				}
			}
		}

		gcpCreds, err := getUserGCPCredentials(ctx, db, box, ws.ID)
		if gcpCreds != nil {
			key := "gcp:" + ws.ID
			if err != nil || gcpCreds.ServiceAccountJSON == "" {
				if shouldNotifyCloudCredential(ctx, db, key, false) {
					for _, username := range recipients {
						_, _ = createNotification(ctx, db, username, "GCP credentials missing",
							fmt.Sprintf("Scope %s is missing GCP credentials. Re-enter them in Settings.", ws.Name),
							"warning", "cloud-credentials", "/dashboard/settings", "high")
					}
				}
			} else {
				payload, parseErr := parseGCPServiceAccountJSON(gcpCreds.ServiceAccountJSON)
				if parseErr != nil {
					if shouldNotifyCloudCredential(ctx, db, key, false) {
						for _, username := range recipients {
							_, _ = createNotification(ctx, db, username, "GCP credentials invalid",
								fmt.Sprintf("Scope %s has invalid GCP credentials. Re-upload JSON in Settings.", ws.Name),
								"warning", "cloud-credentials", "/dashboard/settings", "high")
						}
					}
				} else {
					validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
					_, tokenErr := fetchGCPAccessToken(validateCtx, payload)
					cancel()
					if tokenErr != nil {
						if shouldNotifyCloudCredential(ctx, db, key, false) {
							for _, username := range recipients {
								_, _ = createNotification(ctx, db, username, "GCP credentials invalid",
									fmt.Sprintf("Scope %s failed GCP validation. Re-upload JSON in Settings.", ws.Name),
									"warning", "cloud-credentials", "/dashboard/settings", "high")
							}
						}
					} else {
						shouldNotifyCloudCredential(ctx, db, key, true)
					}
				}
			}
		}
	}
	return nil
}

func updateUserMaintenanceFields(ctx context.Context, db *sql.DB, ws scopeRecord) error {
	if db == nil {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, `UPDATE sf_owner_contexts SET
  gitea_owner=$2,
  gitea_repo=$3,
  artifacts_bucket=$4,
  default_branch=$5,
  updated_at=now()
WHERE id=$1`,
		strings.TrimSpace(ws.ID),
		strings.TrimSpace(ws.GiteaOwner),
		strings.TrimSpace(ws.GiteaRepo),
		nullIfEmpty(strings.TrimSpace(ws.ArtifactsBucket)),
		nullIfEmpty(strings.TrimSpace(ws.DefaultBranch)),
	)
	return err
}

func scopeNotificationRecipients(ws scopeRecord) []string {
	recipients := map[string]struct{}{}
	add := func(u string) {
		u = strings.ToLower(strings.TrimSpace(u))
		if !isValidUsername(u) {
			return
		}
		recipients[u] = struct{}{}
	}
	add(ws.CreatedBy)
	for _, u := range ws.Owners {
		add(u)
	}
	out := make([]string, 0, len(recipients))
	for u := range recipients {
		out = append(out, u)
	}
	sort.Strings(out)
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

func syncGiteaCollaborators(client *gitea.Client, cfg skyforgecore.Config, ws scopeRecord) {
	if client == nil {
		return
	}
	owner := strings.TrimSpace(ws.GiteaOwner)
	repo := strings.TrimSpace(ws.GiteaRepo)
	if owner == "" || repo == "" {
		return
	}

	desired := map[string]string{}
	add := func(user, perm string) {
		user = strings.ToLower(strings.TrimSpace(user))
		if !isValidUsername(user) {
			return
		}
		if strings.EqualFold(user, cfg.Scopes.GiteaUsername) {
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

	add(ws.CreatedBy, "admin")
	for _, u := range ws.Owners {
		add(u, "admin")
	}
	for _, u := range ws.Editors {
		add(u, "write")
	}
	for _, u := range ws.Viewers {
		add(u, "read")
	}

	for user, perm := range desired {
		_ = client.EnsureCollaborator(owner, repo, user, perm)
	}

	current, err := client.ListCollaborators(owner, repo)
	if err != nil {
		return
	}
	for _, user := range current {
		u := strings.ToLower(strings.TrimSpace(user))
		if u == "" || strings.EqualFold(u, cfg.Scopes.GiteaUsername) {
			continue
		}
		if _, ok := desired[u]; ok {
			continue
		}
		_ = client.RemoveCollaborator(owner, repo, u)
	}
}

func ensureAuditActor(ctx context.Context, db *sql.DB, username string) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || db == nil {
		return
	}
	_, _ = db.ExecContext(ctx, `INSERT INTO sf_users (username, created_at) VALUES ($1, now()) ON CONFLICT (username) DO NOTHING`, username)
}

func writeAuditEvent(ctx context.Context, db *sql.DB, actor string, actorIsAdmin bool, impersonated string, action string, scopeID string, details string) {
	if db == nil {
		return
	}
	actor = strings.ToLower(strings.TrimSpace(actor))
	impersonated = strings.ToLower(strings.TrimSpace(impersonated))
	action = strings.TrimSpace(action)
	scopeID = strings.TrimSpace(scopeID)
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
	_, _ = db.ExecContext(ctx, `INSERT INTO sf_audit_log (
  actor_username, actor_is_admin, impersonated_username, action, owner_id, details
) VALUES ($1,$2,NULLIF($3,''),$4,NULLIF($5,''),NULLIF($6,''))`,
		actor, actorIsAdmin, impersonated, action, scopeID, details,
	)
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

func notifyNotificationUpdatePG(ctx context.Context, db *sql.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if db == nil || username == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, "SELECT pg_notify($1, $2)", pgNotifyNotificationsChannel, username)
	return err
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

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

type awsSSOTokenRecord struct {
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

func loadAwsSSOTokens(ctx context.Context, db *sql.DB) (map[string]awsSSOTokenRecord, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT username, refresh_token, refresh_token_expires_at FROM sf_aws_sso_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]awsSSOTokenRecord{}
	for rows.Next() {
		var username string
		var refreshToken sql.NullString
		var refreshExpires sql.NullTime
		if err := rows.Scan(&username, &refreshToken, &refreshExpires); err != nil {
			return nil, err
		}
		rec := awsSSOTokenRecord{RefreshToken: refreshToken.String}
		if refreshExpires.Valid {
			rec.RefreshTokenExpiresAt = refreshExpires.Time
		}
		out[username] = rec
	}
	return out, rows.Err()
}

func loadUsersForMaintenance(ctx context.Context, db *sql.DB) ([]scopeRecord, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id, slug, name, created_by, is_public, default_branch, artifacts_bucket, gitea_owner, gitea_repo, aws_auth_method, aws_region
FROM sf_owner_contexts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []scopeRecord{}
	wsByID := map[string]*scopeRecord{}
	for rows.Next() {
		var rec scopeRecord
		var defaultBranch sql.NullString
		var artifactsBucket sql.NullString
		var giteaOwner, giteaRepo sql.NullString
		var awsAuthMethod, awsRegion sql.NullString
		if err := rows.Scan(&rec.ID, &rec.Slug, &rec.Name, &rec.CreatedBy, &rec.IsPublic, &defaultBranch, &artifactsBucket, &giteaOwner, &giteaRepo, &awsAuthMethod, &awsRegion); err != nil {
			return nil, err
		}
		rec.DefaultBranch = defaultBranch.String
		rec.ArtifactsBucket = artifactsBucket.String
		rec.GiteaOwner = giteaOwner.String
		rec.GiteaRepo = giteaRepo.String
		rec.AWSAuthMethod = awsAuthMethod.String
		rec.AWSRegion = awsRegion.String
		out = append(out, rec)
		wsByID[rec.ID] = &out[len(out)-1]
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	memberRows, err := db.QueryContext(ctx, `SELECT owner_id, username, role FROM sf_owner_members ORDER BY owner_id, username`)
	if err != nil {
		return nil, err
	}
	defer memberRows.Close()
	for memberRows.Next() {
		var wid, username, role string
		if err := memberRows.Scan(&wid, &username, &role); err != nil {
			return nil, err
		}
		ws := wsByID[wid]
		if ws == nil {
			continue
		}
		switch role {
		case "owner":
			ws.Owners = append(ws.Owners, username)
		case "editor":
			ws.Editors = append(ws.Editors, username)
		case "viewer":
			ws.Viewers = append(ws.Viewers, username)
		}
	}
	if err := memberRows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type awsStaticCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func getUserAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretbox.Box, scopeID string) (*awsStaticCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return nil, fmt.Errorf("scope id is required")
	}
	var akid, sak, st sql.NullString
	err := db.QueryRowContext(ctx, `SELECT access_key_id, secret_access_key, session_token
FROM sf_owner_aws_static_credentials WHERE owner_id=$1`, scopeID).Scan(&akid, &sak, &st)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	accessKeyID, err := box.Decrypt(akid.String)
	if err != nil {
		return nil, err
	}
	secretAccessKey, err := box.Decrypt(sak.String)
	if err != nil {
		return nil, err
	}
	sessionToken, err := box.Decrypt(st.String)
	if err != nil {
		return nil, err
	}
	return &awsStaticCredentials{
		AccessKeyID:     strings.TrimSpace(accessKeyID),
		SecretAccessKey: strings.TrimSpace(secretAccessKey),
		SessionToken:    strings.TrimSpace(sessionToken),
	}, nil
}

func validateAWSStaticCredentials(ctx context.Context, region string, creds *awsStaticCredentials) error {
	if creds == nil {
		return fmt.Errorf("missing credentials")
	}
	region = strings.TrimSpace(region)
	if region == "" {
		region = "us-east-1"
	}
	awsCfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)),
	)
	if err != nil {
		return err
	}
	client := sts.NewFromConfig(awsCfg)
	_, err = client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}

type azureServicePrincipal struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

func getUserAzureCredentials(ctx context.Context, db *sql.DB, box *secretbox.Box, scopeID string) (*azureServicePrincipal, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return nil, fmt.Errorf("scope id is required")
	}
	var tenantID, clientID, clientSecret, subscriptionID sql.NullString
	err := db.QueryRowContext(ctx, `SELECT tenant_id, client_id, client_secret, subscription_id
FROM sf_owner_azure_credentials WHERE owner_id=$1`, scopeID).Scan(&tenantID, &clientID, &clientSecret, &subscriptionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	secret, err := box.Decrypt(clientSecret.String)
	if err != nil {
		return nil, err
	}
	return &azureServicePrincipal{
		TenantID:       strings.TrimSpace(tenantID.String),
		ClientID:       strings.TrimSpace(clientID.String),
		ClientSecret:   strings.TrimSpace(secret),
		SubscriptionID: strings.TrimSpace(subscriptionID.String),
	}, nil
}

type gcpServiceAccount struct {
	ServiceAccountJSON string
}

func getUserGCPCredentials(ctx context.Context, db *sql.DB, box *secretbox.Box, scopeID string) (*gcpServiceAccount, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return nil, fmt.Errorf("scope id is required")
	}
	var jsonBlob sql.NullString
	err := db.QueryRowContext(ctx, `SELECT service_account_json FROM sf_owner_gcp_credentials WHERE owner_id=$1`, scopeID).Scan(&jsonBlob)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decoded, err := box.Decrypt(jsonBlob.String)
	if err != nil {
		return nil, err
	}
	return &gcpServiceAccount{ServiceAccountJSON: strings.TrimSpace(decoded)}, nil
}

// GCP/Azure token helpers (copied from skyforge/cloud_validation_api.go)

type gcpServiceAccountPayload struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	TokenURI    string `json:"token_uri"`
}

func parseGCPServiceAccountJSON(raw string) (*gcpServiceAccountPayload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("service account json is empty")
	}
	var payload gcpServiceAccountPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	payload.ClientEmail = strings.TrimSpace(payload.ClientEmail)
	payload.PrivateKey = strings.TrimSpace(payload.PrivateKey)
	payload.ProjectID = strings.TrimSpace(payload.ProjectID)
	payload.TokenURI = strings.TrimSpace(payload.TokenURI)
	if payload.ClientEmail == "" || payload.PrivateKey == "" {
		return nil, fmt.Errorf("service account json missing required fields")
	}
	return &payload, nil
}

func fetchAzureToken(ctx context.Context, tenantID string, clientID string, clientSecret string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("missing azure token params")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "https://management.azure.com/.default")
	u := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure token request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if token, ok := parsed["access_token"].(string); ok && strings.TrimSpace(token) != "" {
		return token, nil
	}
	return "", fmt.Errorf("azure token missing access_token")
}

func fetchGCPAccessToken(ctx context.Context, payload *gcpServiceAccountPayload) (string, error) {
	if payload == nil {
		return "", fmt.Errorf("missing gcp payload")
	}
	assertion, err := buildGCPJWTAssertion(payload)
	if err != nil {
		return "", err
	}
	tokenURL := payload.TokenURI
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("gcp token request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if token, ok := parsed["access_token"].(string); ok && strings.TrimSpace(token) != "" {
		return token, nil
	}
	return "", fmt.Errorf("gcp token missing access_token")
}

func buildGCPJWTAssertion(payload *gcpServiceAccountPayload) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":   payload.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   firstNonEmpty(payload.TokenURI, "https://oauth2.googleapis.com/token"),
		"iat":   now.Unix(),
		"exp":   now.Add(55 * time.Minute).Unix(),
	}
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	encodedHeader, err := encodeJWTPart(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := encodeJWTPart(claims)
	if err != nil {
		return "", err
	}
	signingInput := encodedHeader + "." + encodedClaims
	key, err := parseRSAPrivateKey(payload.PrivateKey)
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	encodedSig := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + encodedSig, nil
}

func encodeJWTPart(payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key")
}

func firstNonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
