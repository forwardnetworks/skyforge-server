package skyforge

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type CloudValidateStatusResponse struct {
	Status    string `json:"status"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type CloudAWSValidateRequest struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

// ValidateAwsSSO checks that AWS SSO credentials can mint role credentials.
//
//encore:api auth method=POST path=/api/cloud/aws/validate
func (s *Service) ValidateAwsSSO(ctx context.Context, req *CloudAWSValidateRequest) (*CloudValidateStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	accountID := strings.TrimSpace(req.AccountID)
	roleName := strings.TrimSpace(req.RoleName)
	if accountID == "" || roleName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("accountId and roleName are required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	creds, err := getAWSRoleCredentials(ctx, s.cfg, s.awsStore, user.Username, accountID, roleName)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("aws sso credentials unavailable").Err()
	}
	expiresAt := ""
	if creds != nil && creds.RoleCredentials != nil && creds.RoleCredentials.Expiration > 0 {
		expiresAt = time.UnixMilli(creds.RoleCredentials.Expiration).UTC().Format(time.RFC3339)
	}
	return &CloudValidateStatusResponse{Status: "ok", ExpiresAt: expiresAt}, nil
}

type CloudAzureValidateRequest struct {
	TenantID     string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// ValidateAzureSP verifies Azure service principal credentials.
//
//encore:api auth method=POST path=/api/cloud/azure/validate
func (s *Service) ValidateAzureSP(ctx context.Context, req *CloudAzureValidateRequest) (*CloudValidateStatusResponse, error) {
	_, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	tenantID := strings.TrimSpace(req.TenantID)
	clientID := strings.TrimSpace(req.ClientID)
	clientSecret := strings.TrimSpace(req.ClientSecret)
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("tenantId, clientId, and clientSecret are required").Err()
	}
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID))
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "https://management.azure.com/.default")
	form.Set("grant_type", "client_credentials")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("azure validation failed").Err()
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("azure validation failed").Err()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("azure credentials rejected").Err()
	}
	return &CloudValidateStatusResponse{Status: "ok"}, nil
}

type AzureSubscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
}

type CloudAzureSubscriptionsResponse struct {
	Subscriptions []AzureSubscription `json:"subscriptions"`
}

// ListAzureSubscriptions returns available subscriptions for the provided service principal.
//
//encore:api auth method=POST path=/api/cloud/azure/subscriptions
func (s *Service) ListAzureSubscriptions(ctx context.Context, req *CloudAzureValidateRequest) (*CloudAzureSubscriptionsResponse, error) {
	_, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	tenantID := strings.TrimSpace(req.TenantID)
	clientID := strings.TrimSpace(req.ClientID)
	clientSecret := strings.TrimSpace(req.ClientSecret)
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("tenantId, clientId, and clientSecret are required").Err()
	}
	token, err := fetchAzureToken(ctx, tenantID, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://management.azure.com/subscriptions?api-version=2020-01-01", nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("azure subscriptions failed").Err()
	}
	reqHTTP.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("azure subscriptions failed").Err()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("azure credentials rejected").Err()
	}
	var payload struct {
		Value []AzureSubscription `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("azure subscriptions failed").Err()
	}
	return &CloudAzureSubscriptionsResponse{Subscriptions: payload.Value}, nil
}

type CloudGCPValidateRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
}

// ValidateGCPServiceAccount verifies GCP service identity JSON by minting a token.
//
//encore:api auth method=POST path=/api/cloud/gcp/validate
func (s *Service) ValidateGCPServiceAccount(ctx context.Context, req *CloudGCPValidateRequest) (*CloudValidateStatusResponse, error) {
	_, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.ServiceAccountJSON) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("serviceAccountJson is required").Err()
	}
	payload, err := parseGCPServiceAccountJSON(req.ServiceAccountJSON)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid service identity json").Err()
	}
	assertion, err := buildGCPJWTAssertion(payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp token signing failed").Err()
	}
	tokenURL := payload.TokenURI
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp validation failed").Err()
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp validation failed").Err()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("gcp credentials rejected").Err()
	}
	return &CloudValidateStatusResponse{Status: "ok"}, nil
}

type GCPProject struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
	Lifecycle string `json:"lifecycleState"`
}

type CloudGCPProjectsResponse struct {
	Projects []GCPProject `json:"projects"`
}

// ListGCPProjects returns accessible projects for the provided service identity.
//
//encore:api auth method=POST path=/api/cloud/gcp/projects
func (s *Service) ListGCPProjects(ctx context.Context, req *CloudGCPValidateRequest) (*CloudGCPProjectsResponse, error) {
	_, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.ServiceAccountJSON) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("serviceAccountJson is required").Err()
	}
	payload, err := parseGCPServiceAccountJSON(req.ServiceAccountJSON)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid service identity json").Err()
	}
	token, err := fetchGCPAccessToken(ctx, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp token request failed").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudresourcemanager.googleapis.com/v1/projects", nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp resource list failed").Err()
	}
	reqHTTP.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp resource list failed").Err()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if payload.ProjectID != "" {
				return &CloudGCPProjectsResponse{Projects: []GCPProject{
					{ProjectID: payload.ProjectID, Name: payload.ProjectID, Lifecycle: "ACTIVE"},
				}}, nil
			}
			return nil, errs.B().Code(errs.Unauthenticated).Msg("gcp credentials rejected").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp resource list failed").Err()
	}
	var payloadResp struct {
		Projects []GCPProject `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payloadResp); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("gcp resource list failed").Err()
	}
	return &CloudGCPProjectsResponse{Projects: payloadResp.Projects}, nil
}

type gcpServiceAccountPayload struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	TokenURI    string `json:"token_uri"`
}

func parseGCPServiceAccountJSON(raw string) (*gcpServiceAccountPayload, error) {
	var payload gcpServiceAccountPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	payload.ClientEmail = strings.TrimSpace(payload.ClientEmail)
	payload.PrivateKey = strings.TrimSpace(payload.PrivateKey)
	payload.ProjectID = strings.TrimSpace(payload.ProjectID)
	payload.TokenURI = strings.TrimSpace(payload.TokenURI)
	if payload.ClientEmail == "" || payload.PrivateKey == "" {
		return nil, fmt.Errorf("missing required fields")
	}
	return &payload, nil
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

func fetchAzureToken(ctx context.Context, tenantID string, clientID string, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID))
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "https://management.azure.com/.default")
	form.Set("grant_type", "client_credentials")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("azure token failed").Err()
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("azure token failed").Err()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errs.B().Code(errs.Unauthenticated).Msg("azure credentials rejected").Err()
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("azure token failed").Err()
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", errs.B().Code(errs.Unavailable).Msg("azure token missing").Err()
	}
	return payload.AccessToken, nil
}

func fetchGCPAccessToken(ctx context.Context, payload *gcpServiceAccountPayload) (string, error) {
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errs.B().Code(errs.Unauthenticated).Msg("gcp credentials rejected").Err()
	}
	var payloadResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payloadResp); err != nil {
		return "", err
	}
	if strings.TrimSpace(payloadResp.AccessToken) == "" {
		return "", errs.B().Code(errs.Unavailable).Msg("gcp token missing").Err()
	}
	return payloadResp.AccessToken, nil
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
