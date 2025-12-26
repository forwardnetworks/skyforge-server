package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type AwsSSOConfigResponse struct {
	Configured bool   `json:"configured"`
	StartURL   string `json:"startUrl,omitempty"`
	Region     string `json:"region,omitempty"`
	AccountID  string `json:"accountId,omitempty"`
	RoleName   string `json:"roleName,omitempty"`
	User       string `json:"user"`
}

type AwsSSOStatusResponse struct {
	Configured          bool   `json:"configured"`
	Connected           bool   `json:"connected"`
	User                string `json:"user"`
	ExpiresAt           string `json:"expiresAt,omitempty"`
	LastAuthenticatedAt string `json:"lastAuthenticatedAt,omitempty"`
}

type AwsSSOStartResponse struct {
	RequestID               string `json:"requestId"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	ExpiresAt               string `json:"expiresAt"`
	IntervalSeconds         int32  `json:"intervalSeconds"`
}

type AwsSSOPollParams struct {
	RequestID string `json:"requestId"`
}

type AwsSSOPollResponse struct {
	Status    string `json:"status"`
	Connected bool   `json:"connected,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	StartURL  string `json:"startUrl,omitempty"`
	Region    string `json:"region,omitempty"`
	User      string `json:"user,omitempty"`
}

type AwsSSOLogoutResponse struct {
	Status string `json:"status"`
}

// GetAwsSSOConfig returns the configured AWS SSO start URL and region.
//
//encore:api auth method=GET path=/api/aws/sso/config
func (s *Service) GetAwsSSOConfig(ctx context.Context) (*AwsSSOConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	_ = ctx
	return &AwsSSOConfigResponse{
		Configured: s.cfg.AwsSSOStartURL != "" && s.cfg.AwsSSORegion != "",
		StartURL:   s.cfg.AwsSSOStartURL,
		Region:     s.cfg.AwsSSORegion,
		AccountID:  s.cfg.AwsSSOAccountID,
		RoleName:   s.cfg.AwsSSORoleName,
		User:       user.Username,
	}, nil
}

// GetAwsSSOConfigV1 returns the configured AWS SSO start URL and region (v1 alias).
//
//encore:api auth method=GET path=/api/v1/aws/sso/config
func (s *Service) GetAwsSSOConfigV1(ctx context.Context) (*AwsSSOConfigResponse, error) {
	return s.GetAwsSSOConfig(ctx)
}

// GetAwsSSOStatus returns connection status for the authenticated user.
//
//encore:api auth method=GET path=/api/aws/sso/status
func (s *Service) GetAwsSSOStatus(ctx context.Context) (*AwsSSOStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	record, err := s.awsStore.get(user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load aws sso status").Err()
	}
	connected := record != nil && strings.TrimSpace(record.RefreshToken) != ""
	resp := &AwsSSOStatusResponse{
		Configured: s.cfg.AwsSSOStartURL != "" && s.cfg.AwsSSORegion != "",
		Connected:  connected,
		User:       user.Username,
	}
	if record != nil && !record.AccessTokenExpiresAt.IsZero() {
		resp.ExpiresAt = record.AccessTokenExpiresAt.UTC().Format(time.RFC3339)
	}
	if record != nil && !record.LastAuthenticatedAtUTC.IsZero() {
		resp.LastAuthenticatedAt = record.LastAuthenticatedAtUTC.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

// GetAwsSSOStatusV1 returns connection status for the authenticated user (v1 alias).
//
//encore:api auth method=GET path=/api/v1/aws/sso/status
func (s *Service) GetAwsSSOStatusV1(ctx context.Context) (*AwsSSOStatusResponse, error) {
	return s.GetAwsSSOStatus(ctx)
}

// StartAwsSSO begins the AWS device authorization flow.
//
//encore:api auth method=POST path=/api/aws/sso/start
func (s *Service) StartAwsSSO(ctx context.Context) (*AwsSSOStartResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	requestID, session, err := startAWSDeviceAuthorization(ctx, s.cfg, s.awsStore, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to start aws sso authorization").Err()
	}
	return &AwsSSOStartResponse{
		RequestID:               requestID,
		VerificationURIComplete: session.VerificationURIComplete,
		UserCode:                session.UserCode,
		ExpiresAt:               session.ExpiresAt.UTC().Format(time.RFC3339),
		IntervalSeconds:         session.IntervalSeconds,
	}, nil
}

// StartAwsSSOV1 begins the AWS device authorization flow (v1 alias).
//
//encore:api auth method=POST path=/api/v1/aws/sso/start
func (s *Service) StartAwsSSOV1(ctx context.Context) (*AwsSSOStartResponse, error) {
	return s.StartAwsSSO(ctx)
}

// PollAwsSSO polls for device authorization completion.
//
//encore:api auth method=POST path=/api/aws/sso/poll
func (s *Service) PollAwsSSO(ctx context.Context, params *AwsSSOPollParams) (*AwsSSOPollResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if params == nil || strings.TrimSpace(params.RequestID) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("requestId is required").Err()
	}
	requestID := strings.TrimSpace(params.RequestID)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	session, token, status, err := pollAWSDeviceToken(ctx, requestID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("aws sso poll failed").Err()
	}
	if session == nil || session.Username != user.Username {
		return nil, errs.B().Code(errs.NotFound).Msg("not found").Err()
	}
	if status != "pending" {
		awsDeviceAuthCache.mu.Lock()
		delete(awsDeviceAuthCache.items, requestID)
		awsDeviceAuthCache.mu.Unlock()
	}
	if status != "ok" {
		return &AwsSSOPollResponse{Status: status}, nil
	}
	record := awsSSOTokenRecord{
		StartURL:               session.StartURL,
		Region:                 session.Region,
		AccessToken:            aws.ToString(token.AccessToken),
		AccessTokenExpiresAt:   time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).UTC(),
		RefreshToken:           aws.ToString(token.RefreshToken),
		LastAuthenticatedAtUTC: time.Now().UTC(),
	}
	if err := s.awsStore.put(user.Username, record); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist aws sso token").Err()
	}
	return &AwsSSOPollResponse{
		Status:    "ok",
		Connected: true,
		ExpiresAt: record.AccessTokenExpiresAt.UTC().Format(time.RFC3339),
		StartURL:  record.StartURL,
		Region:    record.Region,
		User:      user.Username,
	}, nil
}

// PollAwsSSOV1 polls for device authorization completion (v1 alias).
//
//encore:api auth method=POST path=/api/v1/aws/sso/poll
func (s *Service) PollAwsSSOV1(ctx context.Context, params *AwsSSOPollParams) (*AwsSSOPollResponse, error) {
	return s.PollAwsSSO(ctx, params)
}

// LogoutAwsSSO clears any stored AWS SSO tokens.
//
//encore:api auth method=POST path=/api/aws/sso/logout
func (s *Service) LogoutAwsSSO(ctx context.Context) (*AwsSSOLogoutResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if err := s.awsStore.clear(user.Username); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to clear aws sso token").Err()
	}
	return &AwsSSOLogoutResponse{Status: "logged out"}, nil
}

// LogoutAwsSSOV1 clears any stored AWS SSO tokens (v1 alias).
//
//encore:api auth method=POST path=/api/v1/aws/sso/logout
func (s *Service) LogoutAwsSSOV1(ctx context.Context) (*AwsSSOLogoutResponse, error) {
	return s.LogoutAwsSSO(ctx)
}
