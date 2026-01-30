package skyforge

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"encore.dev/beta/errs"
)

type UserGeminiConfigResponse struct {
	Enabled     bool   `json:"enabled"`
	Configured  bool   `json:"configured"`
	Email       string `json:"email,omitempty"`
	Scopes      string `json:"scopes,omitempty"`
	HasToken    bool   `json:"hasToken"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
	RedirectURL string `json:"redirectUrl,omitempty"`
}

type userGeminiOAuthRow struct {
	Username        string
	Email           string
	Scopes          string
	RefreshTokenEnc string
	UpdatedAt       time.Time
}

const (
	geminiStateCookie = "skyforge_gemini_oauth_state"
)

var geminiOAuthRetryableErrors = map[string]bool{
	"account_selection_required": true,
	"consent_required":           true,
	"interaction_required":       true,
	"login_required":             true,
}

func geminiOAuthConfig(cfg Config) (*oauth2.Config, error) {
	if !cfg.GeminiEnabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.GeminiClientID) == "" || strings.TrimSpace(cfg.GeminiClientSecret) == "" {
		return nil, nil
	}
	redirect := strings.TrimSpace(cfg.GeminiRedirectURL)
	if redirect == "" {
		return nil, nil
	}
	return &oauth2.Config{
		ClientID:     cfg.GeminiClientID,
		ClientSecret: cfg.GeminiClientSecret,
		RedirectURL:  redirect,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"openid",
			"email",
			"profile",
			// Wide scope required for Vertex AI / Gemini API usage in most org setups.
			// We can narrow this later once we settle on the specific Gemini API surface.
			"https://www.googleapis.com/auth/cloud-platform",
		},
	}, nil
}

func getUserGeminiOAuth(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userGeminiOAuthRow, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	var email, scopes, refreshEnc sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT email, scopes, refresh_token_enc, updated_at
FROM sf_user_gemini_oauth WHERE username=$1`, username).Scan(&email, &scopes, &refreshEnc, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}
	refreshToken, err := box.decrypt(refreshEnc.String)
	if err != nil {
		log.Printf("gemini decrypt refresh token (%s): %v", username, err)
		return nil, nil
	}
	row := &userGeminiOAuthRow{
		Username:        username,
		Email:           strings.TrimSpace(email.String),
		Scopes:          strings.TrimSpace(scopes.String),
		RefreshTokenEnc: strings.TrimSpace(refreshToken),
	}
	if updatedAt.Valid {
		row.UpdatedAt = updatedAt.Time
	}
	return row, nil
}

func putUserGeminiOAuth(ctx context.Context, db *sql.DB, box *secretBox, username string, email string, scopes string, refreshToken string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return fmt.Errorf("refresh token is required")
	}
	encRefresh, err := encryptIfPlain(box, refreshToken)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_gemini_oauth (username, email, scopes, refresh_token_enc, updated_at)
VALUES ($1,$2,$3,$4,NOW())
ON CONFLICT (username) DO UPDATE
SET email=EXCLUDED.email,
    scopes=EXCLUDED.scopes,
    refresh_token_enc=EXCLUDED.refresh_token_enc,
    updated_at=NOW()`,
		username, email, strings.TrimSpace(scopes), encRefresh,
	)
	return err
}

func deleteUserGeminiOAuth(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_gemini_oauth WHERE username=$1`, username)
	if isMissingDBRelation(err) {
		return nil
	}
	return err
}

// GetUserGeminiConfig returns the current user's Gemini integration status.
//
//encore:api auth method=GET path=/api/user/integrations/gemini
func (s *Service) GetUserGeminiConfig(ctx context.Context) (*UserGeminiConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !s.cfg.GeminiEnabled {
		return &UserGeminiConfigResponse{Enabled: false, Configured: false, HasToken: false}, nil
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	cfg, err := geminiOAuthConfig(s.cfg)
	if err != nil || cfg == nil {
		return &UserGeminiConfigResponse{Enabled: true, Configured: false, HasToken: false}, nil
	}
	box := newSecretBox(s.cfg.SessionSecret)
	ctxDB, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserGeminiOAuth(ctxDB, s.db, box, user.Username)
	if err != nil {
		log.Printf("gemini get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Gemini config").Err()
	}
	resp := &UserGeminiConfigResponse{
		Enabled:     true,
		Configured:  rec != nil && rec.RefreshTokenEnc != "",
		HasToken:    rec != nil && rec.RefreshTokenEnc != "",
		Email:       "",
		Scopes:      "",
		UpdatedAt:   "",
		RedirectURL: cfg.RedirectURL,
	}
	if rec != nil {
		resp.Email = rec.Email
		resp.Scopes = rec.Scopes
		if !rec.UpdatedAt.IsZero() {
			resp.UpdatedAt = rec.UpdatedAt.Format(time.RFC3339Nano)
		}
	}
	return resp, nil
}

func geminiAuthURL(cfg *oauth2.Config, state string, prompt string, loginHint string, hostedDomain string) string {
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if strings.TrimSpace(prompt) != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", strings.TrimSpace(prompt)))
	}
	if strings.TrimSpace(loginHint) != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", strings.TrimSpace(loginHint)))
	}
	if strings.TrimSpace(hostedDomain) != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", strings.TrimSpace(hostedDomain)))
	}
	opts = append(opts, oauth2.SetAuthURLParam("include_granted_scopes", "true"))
	return cfg.AuthCodeURL(state, opts...)
}

// GeminiConnect redirects the user to Google's OAuth consent screen and stores CSRF state in a cookie.
//
//encore:api auth raw method=GET path=/api/user/integrations/gemini/connect
func (s *Service) GeminiConnect(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.cfg.GeminiEnabled {
		http.Error(w, "gemini disabled", http.StatusNotFound)
		return
	}
	cfg, err := geminiOAuthConfig(s.cfg)
	if err != nil || cfg == nil {
		http.Error(w, "gemini oauth not configured", http.StatusPreconditionFailed)
		return
	}

	state, err := randomOIDCString(32)
	if err != nil {
		http.Error(w, "failed to generate oauth state", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     geminiStateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   10 * 60,
		Secure:   s.sessionManager.cookieSecure(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Try to acquire/refresh a token without prompting when possible:
	// - if the user already consented, this should be silent
	// - otherwise, Google redirects back with error=interaction_required,
	//   which we handle by redirecting to a prompt=consent flow in the callback.
	loginHint := strings.TrimSpace(user.Email)
	hostedDomain := strings.TrimSpace(s.cfg.CorpEmailDomain)
	authURL := geminiAuthURL(cfg, state, "none", loginHint, hostedDomain)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GeminiCallback completes the OAuth flow and stores the refresh token for the current user.
//
//encore:api auth raw method=GET path=/api/user/integrations/gemini/callback
func (s *Service) GeminiCallback(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.cfg.GeminiEnabled {
		http.Error(w, "gemini disabled", http.StatusNotFound)
		return
	}
	cfg, err := geminiOAuthConfig(s.cfg)
	if err != nil || cfg == nil {
		http.Error(w, "gemini oauth not configured", http.StatusPreconditionFailed)
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	errParam := strings.TrimSpace(r.URL.Query().Get("error"))
	c, err := r.Cookie(geminiStateCookie)
	if err != nil || strings.TrimSpace(c.Value) == "" || c.Value != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// If we attempted prompt=none, Google may redirect back with an interaction error.
	// Retry once with prompt=consent to perform the one-time consent step.
	if errParam != "" && geminiOAuthRetryableErrors[errParam] {
		if strings.TrimSpace(r.URL.Query().Get("retry")) == "consent" {
			http.Error(w, "oauth requires user interaction", http.StatusUnauthorized)
			return
		}
		loginHint := strings.TrimSpace(user.Email)
		hostedDomain := strings.TrimSpace(s.cfg.CorpEmailDomain)
		consentURL := geminiAuthURL(cfg, state, "consent", loginHint, hostedDomain)
		if strings.Contains(consentURL, "?") {
			consentURL += "&retry=consent"
		} else {
			consentURL += "?retry=consent"
		}
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	if state == "" || code == "" {
		http.Error(w, "missing state/code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		log.Printf("gemini oauth exchange failed: %v", err)
		http.Error(w, "oauth exchange failed", http.StatusUnauthorized)
		return
	}
	refresh := strings.TrimSpace(tok.RefreshToken)

	// Determine user email via id_token when present, otherwise fall back to Skyforge user profile email.
	email := strings.TrimSpace(user.Email)
	if raw, ok := tok.Extra("id_token").(string); ok && raw != "" {
		// Avoid bringing in OIDC verifier; decode minimal claims without validation.
		// This is only used for display.
		parts := strings.Split(raw, ".")
		if len(parts) == 3 {
			if payload, err := base64RawURLDecode(parts[1]); err == nil {
				var claims struct {
					Email string `json:"email"`
				}
				_ = jsonUnmarshal(payload, &claims)
				if strings.TrimSpace(claims.Email) != "" {
					email = strings.TrimSpace(claims.Email)
				}
			}
		}
	}

	scopeStr := strings.Join(cfg.Scopes, " ")
	if v, ok := tok.Extra("scope").(string); ok && strings.TrimSpace(v) != "" {
		scopeStr = strings.TrimSpace(v)
	}

	if s.db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	box := newSecretBox(s.cfg.SessionSecret)
	ctxDB, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if refresh == "" {
		// Google may omit refresh_token on some exchanges. If we already have one stored,
		// keep using it and just update metadata.
		existing, err := getUserGeminiOAuth(ctxDB, s.db, box, user.Username)
		if err != nil {
			log.Printf("gemini get existing refresh: %v", err)
		}
		if existing == nil || strings.TrimSpace(existing.RefreshTokenEnc) == "" {
			http.Error(w, "missing refresh token (reconnect required)", http.StatusBadRequest)
			return
		}
		refresh = strings.TrimSpace(existing.RefreshTokenEnc)
	}

	if err := putUserGeminiOAuth(ctxDB, s.db, box, user.Username, email, scopeStr, refresh); err != nil {
		log.Printf("gemini store failed: %v", err)
		http.Error(w, "failed to store tokens", http.StatusServiceUnavailable)
		return
	}

	// Clear state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     geminiStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.sessionManager.cookieSecure(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/dashboard/gemini", http.StatusFound)
}

// GeminiDisconnect deletes the stored tokens for the current user.
//
//encore:api auth method=POST path=/api/user/integrations/gemini/disconnect
func (s *Service) GeminiDisconnect(ctx context.Context) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctxDB, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteUserGeminiOAuth(ctxDB, s.db, user.Username); err != nil {
		log.Printf("gemini disconnect: %v", err)
		return errs.B().Code(errs.Unavailable).Msg("failed to delete Gemini config").Err()
	}
	return nil
}

// Helpers: keep local to avoid pulling extra deps into this file.
func base64RawURLDecode(s string) ([]byte, error) {
	// RawURLEncoding requires padding stripped.
	return base64.RawURLEncoding.DecodeString(s)
}

func jsonUnmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
