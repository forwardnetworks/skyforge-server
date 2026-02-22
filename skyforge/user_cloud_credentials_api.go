package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserAWSStaticCredentialsGetResponse struct {
	Configured     bool   `json:"configured"`
	AccessKeyLast4 string `json:"accessKeyLast4,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserAWSStaticCredentialsPutRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

// GetUserAWSStaticCredentials returns the current user's AWS static credential status.
//
//encore:api auth method=GET path=/api/me/cloud/aws-static
func (s *Service) GetUserAWSStaticCredentials(ctx context.Context) (*UserAWSStaticCredentialsGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserAWSStaticCredentials(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load aws static credentials").Err()
	}
	last4 := ""
	updatedAt := ""
	if rec != nil {
		if len(rec.AccessKeyID) >= 4 {
			last4 = rec.AccessKeyID[len(rec.AccessKeyID)-4:]
		}
		if !rec.UpdatedAt.IsZero() {
			updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	return &UserAWSStaticCredentialsGetResponse{
		Configured:     rec != nil && rec.AccessKeyID != "" && rec.SecretAccessKey != "",
		AccessKeyLast4: last4,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutUserAWSStaticCredentials saves AWS static credentials for the current user.
//
//encore:api auth method=PUT path=/api/me/cloud/aws-static
func (s *Service) PutUserAWSStaticCredentials(ctx context.Context, req *UserAWSStaticCredentialsPutRequest) (*UserAWSStaticCredentialsGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := putUserAWSStaticCredentials(ctx, s.db, s.box, user.Username, req.AccessKeyID, req.SecretAccessKey); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return s.GetUserAWSStaticCredentials(ctx)
}

// DeleteUserAWSStaticCredentials deletes AWS static credentials for the current user.
//
//encore:api auth method=DELETE path=/api/me/cloud/aws-static
func (s *Service) DeleteUserAWSStaticCredentials(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserAWSStaticCredentials(ctx, s.db, user.Username); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to delete aws static credentials").Err()
	}
	return nil
}

type UserAWSSSOCredentialsResponse struct {
	Configured bool   `json:"configured"`
	StartURL   string `json:"startUrl,omitempty"`
	Region     string `json:"region,omitempty"`
	AccountID  string `json:"accountId,omitempty"`
	RoleName   string `json:"roleName,omitempty"`
	UpdatedAt  string `json:"updatedAt,omitempty"`
}

type UserAWSSSOCredentialsPutRequest struct {
	StartURL  string `json:"startUrl"`
	Region    string `json:"region"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

// GetUserAWSSSOCredentials returns the current user's AWS SSO configuration (non-token).
//
//encore:api auth method=GET path=/api/me/cloud/aws-sso
func (s *Service) GetUserAWSSSOCredentials(ctx context.Context) (*UserAWSSSOCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserAWSSSOCredentials(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load aws sso config").Err()
	}
	if rec == nil {
		return &UserAWSSSOCredentialsResponse{Configured: false}, nil
	}
	updatedAt := ""
	if !rec.UpdatedAt.IsZero() {
		updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return &UserAWSSSOCredentialsResponse{
		Configured: rec.StartURL != "" && rec.Region != "" && rec.AccountID != "" && rec.RoleName != "",
		StartURL:   rec.StartURL,
		Region:     rec.Region,
		AccountID:  rec.AccountID,
		RoleName:   rec.RoleName,
		UpdatedAt:  updatedAt,
	}, nil
}

// PutUserAWSSSOCredentials saves AWS SSO configuration (non-token) for the current user.
//
//encore:api auth method=PUT path=/api/me/cloud/aws-sso
func (s *Service) PutUserAWSSSOCredentials(ctx context.Context, req *UserAWSSSOCredentialsPutRequest) (*UserAWSSSOCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rec := userAWSSSOCredentials{
		StartURL:  req.StartURL,
		Region:    req.Region,
		AccountID: req.AccountID,
		RoleName:  req.RoleName,
	}
	if err := putUserAWSSSOCredentials(ctx, s.db, s.box, user.Username, rec); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return s.GetUserAWSSSOCredentials(ctx)
}

// DeleteUserAWSSSOCredentials deletes AWS SSO configuration for the current user.
//
//encore:api auth method=DELETE path=/api/me/cloud/aws-sso
func (s *Service) DeleteUserAWSSSOCredentials(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserAWSSSOCredentials(ctx, s.db, user.Username); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to delete aws sso config").Err()
	}
	return nil
}

type UserAzureCredentialsResponse struct {
	Configured      bool   `json:"configured"`
	TenantID        string `json:"tenantId,omitempty"`
	ClientID        string `json:"clientId,omitempty"`
	SubscriptionID  string `json:"subscriptionId,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
	HasClientSecret bool   `json:"hasClientSecret"`
}

type UserAzureCredentialsPutRequest struct {
	TenantID       string `json:"tenantId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

// GetUserAzureCredentials returns the current user's Azure credential status.
//
//encore:api auth method=GET path=/api/me/cloud/azure
func (s *Service) GetUserAzureCredentials(ctx context.Context) (*UserAzureCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserAzureCredentials(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load azure credentials").Err()
	}
	if rec == nil {
		return &UserAzureCredentialsResponse{Configured: false, HasClientSecret: false}, nil
	}
	updatedAt := ""
	if !rec.UpdatedAt.IsZero() {
		updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return &UserAzureCredentialsResponse{
		Configured:      rec.TenantID != "" && rec.ClientID != "" && rec.ClientSecret != "",
		TenantID:        rec.TenantID,
		ClientID:        rec.ClientID,
		SubscriptionID:  rec.SubscriptionID,
		HasClientSecret: strings.TrimSpace(rec.ClientSecret) != "",
		UpdatedAt:       updatedAt,
	}, nil
}

// PutUserAzureCredentials saves Azure credentials for the current user.
//
//encore:api auth method=PUT path=/api/me/cloud/azure
func (s *Service) PutUserAzureCredentials(ctx context.Context, req *UserAzureCredentialsPutRequest) (*UserAzureCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cred := userAzureCredentials{
		TenantID:       req.TenantID,
		ClientID:       req.ClientID,
		ClientSecret:   req.ClientSecret,
		SubscriptionID: req.SubscriptionID,
	}
	if err := putUserAzureCredentials(ctx, s.db, s.box, user.Username, cred); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return s.GetUserAzureCredentials(ctx)
}

// DeleteUserAzureCredentials deletes Azure credentials for the current user.
//
//encore:api auth method=DELETE path=/api/me/cloud/azure
func (s *Service) DeleteUserAzureCredentials(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserAzureCredentials(ctx, s.db, user.Username); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to delete azure credentials").Err()
	}
	return nil
}

type UserGCPCredentialsResponse struct {
	Configured bool   `json:"configured"`
	HasJSON    bool   `json:"hasServiceAccountJson"`
	UpdatedAt  string `json:"updatedAt,omitempty"`
}

type UserGCPCredentialsPutRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	ProjectIDOverride  string `json:"projectIdOverride,omitempty"`
}

// GetUserGCPCredentials returns the current user's GCP credential status.
//
//encore:api auth method=GET path=/api/me/cloud/gcp
func (s *Service) GetUserGCPCredentials(ctx context.Context) (*UserGCPCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserGCPCredentials(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load gcp credentials").Err()
	}
	updatedAt := ""
	if rec != nil && !rec.UpdatedAt.IsZero() {
		updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return &UserGCPCredentialsResponse{
		Configured: rec != nil && strings.TrimSpace(rec.ServiceAccountJSON) != "",
		HasJSON:    rec != nil && strings.TrimSpace(rec.ServiceAccountJSON) != "",
		UpdatedAt:  updatedAt,
	}, nil
}

// PutUserGCPCredentials saves GCP credentials for the current user.
//
//encore:api auth method=PUT path=/api/me/cloud/gcp
func (s *Service) PutUserGCPCredentials(ctx context.Context, req *UserGCPCredentialsPutRequest) (*UserGCPCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := putUserGCPCredentials(ctx, s.db, s.box, user.Username, req.ServiceAccountJSON, req.ProjectIDOverride); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return s.GetUserGCPCredentials(ctx)
}

// DeleteUserGCPCredentials deletes GCP credentials for the current user.
//
//encore:api auth method=DELETE path=/api/me/cloud/gcp
func (s *Service) DeleteUserGCPCredentials(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserGCPCredentials(ctx, s.db, user.Username); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to delete gcp credentials").Err()
	}
	return nil
}

type UserIBMCredentialsResponse struct {
	Configured      bool   `json:"configured"`
	Region          string `json:"region,omitempty"`
	ResourceGroupID string `json:"resourceGroupId,omitempty"`
	HasAPIKey       bool   `json:"hasApiKey"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
}

type UserIBMCredentialsPutRequest struct {
	APIKey          string `json:"apiKey"`
	Region          string `json:"region"`
	ResourceGroupID string `json:"resourceGroupId,omitempty"`
}

// GetUserIBMCredentials returns the current user's IBM Cloud credential status.
//
//encore:api auth method=GET path=/api/me/cloud/ibm
func (s *Service) GetUserIBMCredentials(ctx context.Context) (*UserIBMCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserIBMCredentials(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load ibm cloud credentials").Err()
	}
	if rec == nil {
		return &UserIBMCredentialsResponse{Configured: false, HasAPIKey: false}, nil
	}
	updatedAt := ""
	if !rec.UpdatedAt.IsZero() {
		updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return &UserIBMCredentialsResponse{
		Configured:      strings.TrimSpace(rec.APIKey) != "" && strings.TrimSpace(rec.Region) != "",
		Region:          rec.Region,
		ResourceGroupID: rec.ResourceGroupID,
		HasAPIKey:       strings.TrimSpace(rec.APIKey) != "",
		UpdatedAt:       updatedAt,
	}, nil
}

// PutUserIBMCredentials saves IBM Cloud credentials for the current user.
//
//encore:api auth method=PUT path=/api/me/cloud/ibm
func (s *Service) PutUserIBMCredentials(ctx context.Context, req *UserIBMCredentialsPutRequest) (*UserIBMCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rec := userIBMCredentials{
		APIKey:          req.APIKey,
		Region:          req.Region,
		ResourceGroupID: req.ResourceGroupID,
	}
	if err := putUserIBMCredentials(ctx, s.db, s.box, user.Username, rec); err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return s.GetUserIBMCredentials(ctx)
}

// DeleteUserIBMCredentials deletes IBM Cloud credentials for the current user.
//
//encore:api auth method=DELETE path=/api/me/cloud/ibm
func (s *Service) DeleteUserIBMCredentials(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserIBMCredentials(ctx, s.db, user.Username); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to delete ibm cloud credentials").Err()
	}
	return nil
}
