package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
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

type AwsSSOAccount struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
}

type AwsSSOAccountsResponse struct {
	Accounts []AwsSSOAccount `json:"accounts"`
}

type AwsSSORole struct {
	RoleName string `json:"roleName"`
}

type AwsSSORolesResponse struct {
	Roles []AwsSSORole `json:"roles"`
}

func awsSSOAccessToken(ctx context.Context, cfg Config, store awsSSOTokenStore, username string) (string, error) {
	if cfg.AwsSSOStartURL == "" || cfg.AwsSSORegion == "" {
		return "", errs.B().Code(errs.FailedPrecondition).Msg("AWS SSO is not configured").Err()
	}
	record, err := store.get(username)
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("failed to load aws sso token").Err()
	}
	if record == nil || strings.TrimSpace(record.RefreshToken) == "" {
		return "", errs.B().Code(errs.FailedPrecondition).Msg("AWS SSO is not connected").Err()
	}
	if record.AccessToken == "" || time.Now().Add(2*time.Minute).After(record.AccessTokenExpiresAt) {
		clientID, clientSecret, _, err := ensureAWSOIDCClient(ctx, cfg, store)
		if err != nil {
			return "", errs.B().Code(errs.Unavailable).Msg("failed to refresh aws sso token").Err()
		}
		refreshed, err := refreshAWSAccessToken(ctx, cfg.AwsSSORegion, clientID, clientSecret, record.RefreshToken)
		if err != nil {
			return "", errs.B().Code(errs.Unavailable).Msg("failed to refresh aws sso token").Err()
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
			return "", errs.B().Code(errs.Unavailable).Msg("failed to persist aws sso token").Err()
		}
	}
	return record.AccessToken, nil
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
	requestID, session, err := startAWSDeviceAuthorization(ctx, s.cfg, s.awsStore, s.db, user.Username)
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
	session, token, status, err := pollAWSDeviceToken(ctx, s.cfg, s.awsStore, s.db, requestID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("aws sso poll failed").Err()
	}
	if session == nil || session.Username != user.Username {
		return nil, errs.B().Code(errs.NotFound).Msg("not found").Err()
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

// ListAwsSSOAccounts returns accounts available for the current SSO session.
//
//encore:api auth method=GET path=/api/aws/sso/accounts
func (s *Service) ListAwsSSOAccounts(ctx context.Context) (*AwsSSOAccountsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	accessToken, err := awsSSOAccessToken(ctx, s.cfg, s.awsStore, user.Username)
	if err != nil {
		return nil, err
	}
	awsCfg, err := awsAnonymousConfig(ctx, s.cfg.AwsSSORegion)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to configure aws sso client").Err()
	}
	client := sso.NewFromConfig(awsCfg)
	pager := sso.NewListAccountsPaginator(client, &sso.ListAccountsInput{
		AccessToken: ptr(accessToken),
	})
	accounts := []AwsSSOAccount{}
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to list aws accounts").Err()
		}
		for _, acct := range page.AccountList {
			accountID := aws.ToString(acct.AccountId)
			if accountID == "" {
				continue
			}
			accounts = append(accounts, AwsSSOAccount{
				AccountID: accountID,
				Name:      aws.ToString(acct.AccountName),
				Email:     aws.ToString(acct.EmailAddress),
			})
		}
	}
	return &AwsSSOAccountsResponse{Accounts: accounts}, nil
}

// ListAwsSSORoles returns roles for a selected AWS account.
//
//encore:api auth method=GET path=/api/aws/sso/accounts/:accountID/roles
func (s *Service) ListAwsSSORoles(ctx context.Context, accountID string) (*AwsSSORolesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("accountID is required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	accessToken, err := awsSSOAccessToken(ctx, s.cfg, s.awsStore, user.Username)
	if err != nil {
		return nil, err
	}
	awsCfg, err := awsAnonymousConfig(ctx, s.cfg.AwsSSORegion)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to configure aws sso client").Err()
	}
	client := sso.NewFromConfig(awsCfg)
	pager := sso.NewListAccountRolesPaginator(client, &sso.ListAccountRolesInput{
		AccessToken: ptr(accessToken),
		AccountId:   ptr(accountID),
	})
	roles := []AwsSSORole{}
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to list aws roles").Err()
		}
		for _, role := range page.RoleList {
			roleName := aws.ToString(role.RoleName)
			if roleName == "" {
				continue
			}
			roles = append(roles, AwsSSORole{RoleName: roleName})
		}
	}
	return &AwsSSORolesResponse{Roles: roles}, nil
}
