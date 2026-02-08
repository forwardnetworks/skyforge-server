package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserElasticConfigResponse struct {
	Enabled          bool   `json:"enabled"`
	Configured       bool   `json:"configured"`
	URL              string `json:"url,omitempty"`
	IndexPrefix      string `json:"indexPrefix,omitempty"`
	AuthType         string `json:"authType,omitempty"` // none | api_key | basic
	HasAPIKey        bool   `json:"hasApiKey"`
	BasicUsername    string `json:"basicUsername,omitempty"`
	HasBasicPassword bool   `json:"hasBasicPassword"`
	VerifyTLS        bool   `json:"verifyTls"`
	UpdatedAt        string `json:"updatedAt,omitempty"`

	DefaultURL         string `json:"defaultUrl,omitempty"`
	DefaultIndexPrefix string `json:"defaultIndexPrefix,omitempty"`
}

type PutUserElasticConfigRequest struct {
	URL           string `json:"url"`
	IndexPrefix   string `json:"indexPrefix"`
	AuthType      string `json:"authType"` // none | api_key | basic
	APIKey        string `json:"apiKey"`
	BasicUsername string `json:"basicUsername"`
	BasicPassword string `json:"basicPassword"`
	VerifyTLS     *bool  `json:"verifyTls"`
}

type UserElasticTestResponse struct {
	Status    string `json:"status"` // ok | error
	Detail    string `json:"detail,omitempty"`
	CheckedAt string `json:"checkedAt,omitempty"`
}

type userElasticConfig struct {
	Username      string
	URL           string
	AuthType      string
	APIKey        string
	BasicUsername string
	BasicPassword string
	IndexPrefix   string
	VerifyTLS     bool
	UpdatedAt     time.Time
}

func (c *userElasticConfig) toAPI(defaultURL, defaultIndexPrefix string, enabled bool) *UserElasticConfigResponse {
	if c == nil {
		return &UserElasticConfigResponse{
			Enabled:            enabled,
			Configured:         false,
			URL:                "",
			IndexPrefix:        "",
			AuthType:           "none",
			HasAPIKey:          false,
			BasicUsername:      "",
			HasBasicPassword:   false,
			VerifyTLS:          true,
			UpdatedAt:          "",
			DefaultURL:         defaultURL,
			DefaultIndexPrefix: defaultIndexPrefix,
		}
	}
	resp := &UserElasticConfigResponse{
		Enabled:            enabled,
		Configured:         true,
		URL:                c.URL,
		IndexPrefix:        c.IndexPrefix,
		AuthType:           c.AuthType,
		HasAPIKey:          strings.TrimSpace(c.APIKey) != "",
		BasicUsername:      c.BasicUsername,
		HasBasicPassword:   strings.TrimSpace(c.BasicPassword) != "",
		VerifyTLS:          c.VerifyTLS,
		DefaultURL:         defaultURL,
		DefaultIndexPrefix: defaultIndexPrefix,
	}
	if !c.UpdatedAt.IsZero() {
		resp.UpdatedAt = c.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return resp
}

func normalizeElasticURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	raw = strings.TrimRight(raw, "/")
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", fmt.Errorf("elastic url must start with http:// or https://")
	}
	return raw, nil
}

func normalizeElasticIndexPrefix(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Keep this permissive; Elasticsearch index naming constraints are enforced
	// during actual indexing. We only normalize obvious path separators.
	raw = strings.ReplaceAll(raw, "/", "-")
	raw = strings.ReplaceAll(raw, "\\", "-")
	return raw
}

func normalizeElasticAuthType(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", "none":
		return "none"
	case "api_key", "apikey":
		return "api_key"
	case "basic":
		return "basic"
	default:
		return "none"
	}
}

func getUserElasticConfig(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userElasticConfig, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	var (
		url, authType, apiKeyEnc, basicUser, basicPassEnc, indexPrefix sql.NullString
		verifyTLS                                                      sql.NullBool
		updatedAt                                                      sql.NullTime
	)
	err := db.QueryRowContext(ctx, `SELECT url, auth_type, api_key_enc, basic_username, basic_password_enc, index_prefix, verify_tls, updated_at
FROM sf_user_elastic_config WHERE username=$1`, username).Scan(&url, &authType, &apiKeyEnc, &basicUser, &basicPassEnc, &indexPrefix, &verifyTLS, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}

	apiKey, _ := box.decrypt(strings.TrimSpace(apiKeyEnc.String))
	basicPass, _ := box.decrypt(strings.TrimSpace(basicPassEnc.String))

	rec := &userElasticConfig{
		Username:      username,
		URL:           strings.TrimSpace(url.String),
		AuthType:      normalizeElasticAuthType(authType.String),
		APIKey:        strings.TrimSpace(apiKey),
		BasicUsername: strings.TrimSpace(basicUser.String),
		BasicPassword: strings.TrimSpace(basicPass),
		IndexPrefix:   strings.TrimSpace(indexPrefix.String),
		VerifyTLS:     true,
	}
	if verifyTLS.Valid {
		rec.VerifyTLS = verifyTLS.Bool
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putUserElasticConfig(ctx context.Context, db *sql.DB, box *secretBox, username string, req PutUserElasticConfigRequest) (*userElasticConfig, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	url, err := normalizeElasticURL(req.URL)
	if err != nil {
		return nil, err
	}
	indexPrefix := normalizeElasticIndexPrefix(req.IndexPrefix)
	authType := normalizeElasticAuthType(req.AuthType)

	verifyTLS := true
	if req.VerifyTLS != nil {
		verifyTLS = *req.VerifyTLS
	}

	// Support partial updates: if the user doesn't provide a new secret, keep the
	// stored one (when switching between auth modes, we clear irrelevant fields).
	var existingAPIKeyEnc, existingBasicPassEnc string
	{
		var apiKeyEncDB, basicPassEncDB sql.NullString
		_ = db.QueryRowContext(ctx, `SELECT api_key_enc, basic_password_enc
FROM sf_user_elastic_config WHERE username=$1`, username).Scan(&apiKeyEncDB, &basicPassEncDB)
		existingAPIKeyEnc = strings.TrimSpace(apiKeyEncDB.String)
		existingBasicPassEnc = strings.TrimSpace(basicPassEncDB.String)
	}

	apiKeyEnc := ""
	basicPassEnc := ""
	basicUser := strings.TrimSpace(req.BasicUsername)

	switch authType {
	case "api_key":
		if strings.TrimSpace(req.APIKey) == "" {
			apiKeyEnc = existingAPIKeyEnc
		} else {
			apiKeyEnc, err = encryptIfPlain(box, req.APIKey)
			if err != nil {
				return nil, err
			}
		}
		basicUser = ""
	case "basic":
		if strings.TrimSpace(req.BasicPassword) == "" {
			basicPassEnc = existingBasicPassEnc
		} else {
			basicPassEnc, err = encryptIfPlain(box, req.BasicPassword)
			if err != nil {
				return nil, err
			}
		}
	default:
		authType = "none"
		basicUser = ""
	}

	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_elastic_config
(username, url, auth_type, api_key_enc, basic_username, basic_password_enc, index_prefix, verify_tls, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
ON CONFLICT (username) DO UPDATE SET
url=EXCLUDED.url,
auth_type=EXCLUDED.auth_type,
api_key_enc=EXCLUDED.api_key_enc,
basic_username=EXCLUDED.basic_username,
basic_password_enc=EXCLUDED.basic_password_enc,
index_prefix=EXCLUDED.index_prefix,
verify_tls=EXCLUDED.verify_tls,
updated_at=EXCLUDED.updated_at`,
		username,
		url,
		authType,
		apiKeyEnc,
		basicUser,
		basicPassEnc,
		indexPrefix,
		verifyTLS,
	)
	if err != nil {
		return nil, err
	}

	return &userElasticConfig{
		Username:      username,
		URL:           url,
		AuthType:      authType,
		APIKey:        strings.TrimSpace(req.APIKey),
		BasicUsername: basicUser,
		BasicPassword: strings.TrimSpace(req.BasicPassword),
		IndexPrefix:   indexPrefix,
		VerifyTLS:     verifyTLS,
		UpdatedAt:     time.Now().UTC(),
	}, nil
}

func clearUserElasticConfig(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return fmt.Errorf("username is required")
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_elastic_config WHERE username=$1`, username)
	if isMissingDBRelation(err) {
		return nil
	}
	return err
}

// GetUserElasticConfig returns the current user's Elastic integration settings.
//
//encore:api auth method=GET path=/api/user/integrations/elastic
func (s *Service) GetUserElasticConfig(ctx context.Context) (*UserElasticConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	// Treat visiting the Elastic integration page as "activity" for autosleep.
	s.touchElasticToolsActivity(ctx)

	enabled := s.cfg.Features.ElasticEnabled
	defaultURL := strings.TrimSpace(s.cfg.ElasticURL)
	defaultIndexPrefix := strings.TrimSpace(s.cfg.ElasticIndexPrefix)

	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxDB, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserElasticConfig(ctxDB, s.db, box, user.Username)
	if err != nil {
		log.Printf("elastic get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Elastic config").Err()
	}
	return rec.toAPI(defaultURL, defaultIndexPrefix, enabled), nil
}

// PutUserElasticConfig upserts the user's Elastic integration settings.
//
//encore:api auth method=PUT path=/api/user/integrations/elastic
func (s *Service) PutUserElasticConfig(ctx context.Context, req *PutUserElasticConfigRequest) (*UserElasticConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	enabled := s.cfg.Features.ElasticEnabled
	defaultURL := strings.TrimSpace(s.cfg.ElasticURL)
	defaultIndexPrefix := strings.TrimSpace(s.cfg.ElasticIndexPrefix)

	box := newSecretBox(s.cfg.SessionSecret)
	ctxDB, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = putUserElasticConfig(ctxDB, s.db, box, user.Username, *req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	// Re-read to avoid leaking secrets while still reporting whether they're stored.
	ctxDB2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserElasticConfig(ctxDB2, s.db, box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reload Elastic config").Err()
	}
	return rec.toAPI(defaultURL, defaultIndexPrefix, enabled), nil
}

// ClearUserElasticConfig removes the user's Elastic integration settings.
//
//encore:api auth method=POST path=/api/user/integrations/elastic/clear
func (s *Service) ClearUserElasticConfig(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctxDB, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := clearUserElasticConfig(ctxDB, s.db, user.Username); err != nil {
		log.Printf("elastic clear: %v", err)
		return errs.B().Code(errs.Unavailable).Msg("failed to clear Elastic config").Err()
	}
	return nil
}

// TestUserElasticConfig does a lightweight health check of the configured Elastic endpoint.
//
//encore:api auth method=POST path=/api/user/integrations/elastic/test
func (s *Service) TestUserElasticConfig(ctx context.Context) (*UserElasticTestResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	// "Test" is an explicit user action; treat it as autosleep activity.
	s.touchElasticToolsActivity(ctx)
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxCfg, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cfg, err := getUserElasticConfig(ctxCfg, s.db, box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Elastic config").Err()
	}

	// If the user hasn't configured anything, fall back to the instance default.
	url := strings.TrimSpace(s.cfg.ElasticURL)
	authType := "none"
	apiKey := ""
	basicUser := ""
	basicPass := ""
	verifyTLS := true
	if cfg != nil && strings.TrimSpace(cfg.URL) != "" {
		url = cfg.URL
		authType = cfg.AuthType
		apiKey = cfg.APIKey
		basicUser = cfg.BasicUsername
		basicPass = cfg.BasicPassword
		verifyTLS = cfg.VerifyTLS
	}
	if url == "" {
		return &UserElasticTestResponse{
			Status:    "error",
			Detail:    "Elastic is not configured",
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	ctxHTTP, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctxHTTP, http.MethodGet, url+"/_cluster/health", nil)
	switch authType {
	case "api_key":
		if strings.TrimSpace(apiKey) != "" {
			req.Header.Set("Authorization", "ApiKey "+strings.TrimSpace(apiKey))
		}
	case "basic":
		if strings.TrimSpace(basicUser) != "" || strings.TrimSpace(basicPass) != "" {
			req.SetBasicAuth(strings.TrimSpace(basicUser), strings.TrimSpace(basicPass))
		}
	}
	// verifyTLS not yet used; keep for future parity with other integrations.
	_ = verifyTLS

	resp, err := http.DefaultClient.Do(req)
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		return &UserElasticTestResponse{Status: "error", Detail: err.Error(), CheckedAt: checkedAt}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &UserElasticTestResponse{Status: "error", Detail: fmt.Sprintf("http %d", resp.StatusCode), CheckedAt: checkedAt}, nil
	}
	return &UserElasticTestResponse{Status: "ok", CheckedAt: checkedAt}, nil
}
