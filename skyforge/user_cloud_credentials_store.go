package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type userAWSStaticCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	UpdatedAt       time.Time
}

func getUserAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userAWSStaticCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var akid, sak sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT access_key_id, secret_access_key, updated_at
FROM sf_user_aws_static_credentials WHERE username=$1`, username).Scan(&akid, &sak, &updatedAt)
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
	out := &userAWSStaticCredentials{
		AccessKeyID:     strings.TrimSpace(accessKeyID),
		SecretAccessKey: strings.TrimSpace(secretAccessKey),
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	return out, nil
}

func putUserAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretBox, username, accessKeyID, secretAccessKey string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	accessKeyID = strings.TrimSpace(accessKeyID)
	secretAccessKey = strings.TrimSpace(secretAccessKey)
	if username == "" {
		return fmt.Errorf("username is required")
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
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_aws_static_credentials (username, access_key_id, secret_access_key, updated_at)
VALUES ($1,$2,$3,now())
ON CONFLICT (username) DO UPDATE SET
  access_key_id=excluded.access_key_id,
  secret_access_key=excluded.secret_access_key,
  updated_at=now()`, username, encAKID, encSAK)
	return err
}

func deleteUserAWSStaticCredentials(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_aws_static_credentials WHERE username=$1`, username)
	return err
}

type userAWSSSOCredentials struct {
	StartURL  string
	Region    string
	AccountID string
	RoleName  string
	UpdatedAt time.Time
}

func getUserAWSSSOCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userAWSSSOCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var startURL, region, accountID, roleName sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT start_url, region, account_id, role_name, updated_at
FROM sf_user_aws_sso_credentials WHERE username=$1`, username).Scan(&startURL, &region, &accountID, &roleName, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decStart, err := box.decrypt(startURL.String)
	if err != nil {
		return nil, err
	}
	decRegion, err := box.decrypt(region.String)
	if err != nil {
		return nil, err
	}
	decAcct, err := box.decrypt(accountID.String)
	if err != nil {
		return nil, err
	}
	decRole, err := box.decrypt(roleName.String)
	if err != nil {
		return nil, err
	}
	out := &userAWSSSOCredentials{
		StartURL:  strings.TrimSpace(decStart),
		Region:    strings.TrimSpace(decRegion),
		AccountID: strings.TrimSpace(decAcct),
		RoleName:  strings.TrimSpace(decRole),
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	return out, nil
}

func putUserAWSSSOCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string, rec userAWSSSOCredentials) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	rec.StartURL = strings.TrimSpace(rec.StartURL)
	rec.Region = strings.TrimSpace(rec.Region)
	rec.AccountID = strings.TrimSpace(rec.AccountID)
	rec.RoleName = strings.TrimSpace(rec.RoleName)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if rec.StartURL == "" || rec.Region == "" || rec.AccountID == "" || rec.RoleName == "" {
		return fmt.Errorf("startUrl, region, accountId, and roleName are required")
	}
	encStart, err := encryptIfPlain(box, rec.StartURL)
	if err != nil {
		return err
	}
	encRegion, err := encryptIfPlain(box, rec.Region)
	if err != nil {
		return err
	}
	encAcct, err := encryptIfPlain(box, rec.AccountID)
	if err != nil {
		return err
	}
	encRole, err := encryptIfPlain(box, rec.RoleName)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_aws_sso_credentials (username, start_url, region, account_id, role_name, updated_at)
VALUES ($1,$2,$3,$4,$5,now())
ON CONFLICT (username) DO UPDATE SET
  start_url=excluded.start_url,
  region=excluded.region,
  account_id=excluded.account_id,
  role_name=excluded.role_name,
  updated_at=now()`, username, encStart, encRegion, encAcct, encRole)
	return err
}

func deleteUserAWSSSOCredentials(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_aws_sso_credentials WHERE username=$1`, username)
	return err
}

type userAzureCredentials struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
	UpdatedAt      time.Time
}

func getUserAzureCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userAzureCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var tenantID, clientID, clientSecret, subscriptionID sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT tenant_id, client_id, client_secret, COALESCE(subscription_id, ''), updated_at
FROM sf_user_azure_credentials WHERE username=$1`, username).Scan(&tenantID, &clientID, &clientSecret, &subscriptionID, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decTenant, err := box.decrypt(tenantID.String)
	if err != nil {
		return nil, err
	}
	decClient, err := box.decrypt(clientID.String)
	if err != nil {
		return nil, err
	}
	decSecret, err := box.decrypt(clientSecret.String)
	if err != nil {
		return nil, err
	}
	sub := strings.TrimSpace(subscriptionID.String)
	if sub != "" {
		if d, err := box.decrypt(sub); err == nil {
			sub = strings.TrimSpace(d)
		}
	}
	out := &userAzureCredentials{
		TenantID:       strings.TrimSpace(decTenant),
		ClientID:       strings.TrimSpace(decClient),
		ClientSecret:   strings.TrimSpace(decSecret),
		SubscriptionID: sub,
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	return out, nil
}

func putUserAzureCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string, cred userAzureCredentials) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	cred.TenantID = strings.TrimSpace(cred.TenantID)
	cred.ClientID = strings.TrimSpace(cred.ClientID)
	cred.ClientSecret = strings.TrimSpace(cred.ClientSecret)
	cred.SubscriptionID = strings.TrimSpace(cred.SubscriptionID)
	if username == "" {
		return fmt.Errorf("username is required")
	}
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
	encSub := ""
	if cred.SubscriptionID != "" {
		encSub, err = encryptIfPlain(box, cred.SubscriptionID)
		if err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_azure_credentials (
  username, tenant_id, client_id, client_secret, subscription_id, updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),now())
ON CONFLICT (username) DO UPDATE SET
  tenant_id=excluded.tenant_id,
  client_id=excluded.client_id,
  client_secret=excluded.client_secret,
  subscription_id=excluded.subscription_id,
  updated_at=now()`, username, encTenant, encClient, encSecret, encSub)
	return err
}

func deleteUserAzureCredentials(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_azure_credentials WHERE username=$1`, username)
	return err
}

type userGCPCredentials struct {
	ServiceAccountJSON string
	ProjectIDOverride  string
	UpdatedAt          time.Time
}

func getUserGCPCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userGCPCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var raw sql.NullString
	var projectOverride sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT service_account_json, COALESCE(project_id_override, ''), updated_at
FROM sf_user_gcp_credentials WHERE username=$1`, username).Scan(&raw, &projectOverride, &updatedAt)
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
	out := &userGCPCredentials{
		ServiceAccountJSON: strings.TrimSpace(decoded),
		ProjectIDOverride:  strings.TrimSpace(projectOverride.String),
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	return out, nil
}

func putUserGCPCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string, jsonBlob, projectOverride string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	jsonBlob = strings.TrimSpace(jsonBlob)
	projectOverride = strings.TrimSpace(projectOverride)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if jsonBlob == "" {
		return fmt.Errorf("serviceAccountJson is required")
	}
	encJSON, err := encryptIfPlain(box, jsonBlob)
	if err != nil {
		return err
	}
	encOverride := ""
	if projectOverride != "" {
		encOverride, err = encryptIfPlain(box, projectOverride)
		if err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_gcp_credentials (
  username, service_account_json, project_id_override, updated_at
) VALUES ($1,$2,NULLIF($3,''),now())
ON CONFLICT (username) DO UPDATE SET
  service_account_json=excluded.service_account_json,
  project_id_override=excluded.project_id_override,
  updated_at=now()`, username, encJSON, encOverride)
	return err
}

func deleteUserGCPCredentials(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_gcp_credentials WHERE username=$1`, username)
	return err
}

type userIBMCredentials struct {
	APIKey          string
	Region          string
	ResourceGroupID string
	UpdatedAt       time.Time
}

func getUserIBMCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userIBMCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var apiKey, region, rg sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT api_key, region, resource_group_id, updated_at
FROM sf_user_ibm_cloud_credentials WHERE username=$1`, username).Scan(&apiKey, &region, &rg, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decKey, err := box.decrypt(apiKey.String)
	if err != nil {
		return nil, err
	}
	decRegion, err := box.decrypt(region.String)
	if err != nil {
		return nil, err
	}
	decRG := strings.TrimSpace(rg.String)
	if decRG != "" {
		if d, err := box.decrypt(decRG); err == nil {
			decRG = strings.TrimSpace(d)
		}
	}
	out := &userIBMCredentials{
		APIKey:          strings.TrimSpace(decKey),
		Region:          strings.TrimSpace(decRegion),
		ResourceGroupID: decRG,
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	return out, nil
}

func putUserIBMCredentials(ctx context.Context, db *sql.DB, box *secretBox, username string, rec userIBMCredentials) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	rec.APIKey = strings.TrimSpace(rec.APIKey)
	rec.Region = strings.TrimSpace(rec.Region)
	rec.ResourceGroupID = strings.TrimSpace(rec.ResourceGroupID)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if rec.APIKey == "" || rec.Region == "" {
		return fmt.Errorf("apiKey and region are required")
	}
	encKey, err := encryptIfPlain(box, rec.APIKey)
	if err != nil {
		return err
	}
	encRegion, err := encryptIfPlain(box, rec.Region)
	if err != nil {
		return err
	}
	encRG := ""
	if rec.ResourceGroupID != "" {
		encRG, err = encryptIfPlain(box, rec.ResourceGroupID)
		if err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_ibm_cloud_credentials (
  username, api_key, region, resource_group_id, updated_at
) VALUES ($1,$2,$3,COALESCE(NULLIF($4,''),''),now())
ON CONFLICT (username) DO UPDATE SET
  api_key=excluded.api_key,
  region=excluded.region,
  resource_group_id=excluded.resource_group_id,
  updated_at=now()`, username, encKey, encRegion, encRG)
	return err
}

func deleteUserIBMCredentials(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_ibm_cloud_credentials WHERE username=$1`, username)
	return err
}
