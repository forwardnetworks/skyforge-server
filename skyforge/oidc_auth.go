package skyforge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"encore.dev"
	"encore.dev/rlog"
)

const (
	oidcStateCookie = "skyforge_oidc_state"
	oidcNonceCookie = "skyforge_oidc_nonce"
	oidcNextCookie  = "skyforge_oidc_next"
)

type OIDCClient struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

func initOIDCClient(cfg Config) (*OIDCClient, error) {
	if strings.TrimSpace(cfg.OIDC.IssuerURL) == "" ||
		strings.TrimSpace(cfg.OIDC.ClientID) == "" ||
		strings.TrimSpace(cfg.OIDC.ClientSecret) == "" ||
		strings.TrimSpace(cfg.OIDC.RedirectURL) == "" {
		rlog.Info("oidc disabled: missing issuer/client/redirect settings")
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	providerURL := strings.TrimSpace(cfg.OIDC.IssuerURL)
	discoveryURL := strings.TrimSpace(cfg.OIDC.DiscoveryURL)
	if raw := strings.TrimSpace(cfg.OIDC.DiscoveryURL); raw != "" {
		// Allow callers to specify either the issuer base or the full discovery URL.
		raw = strings.TrimSuffix(raw, "/.well-known/openid-configuration")
		raw = strings.TrimSuffix(raw, ".well-known/openid-configuration")
		raw = strings.TrimRight(raw, "/")
		if raw != "" {
			providerURL = raw
			// When we fetch discovery from a non-issuer URL (e.g. in-cluster Dex service),
			// allow the discovery document to define the external issuer.
			ctx = oidc.InsecureIssuerURLContext(ctx, cfg.OIDC.IssuerURL)
		}
	}

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, err
	}

	endpoint := provider.Endpoint()
	// If we discovered the provider via an internal address (e.g. http://dex:5556/dex),
	// but the issuer is an external HTTPS hostname (e.g. https://skyforge.../dex),
	// Dex will typically advertise token endpoints using the external issuer URL.
	//
	// That breaks in-cluster token exchange when the Skyforge server does not trust
	// the edge TLS certificate (common in private clusters).
	//
	// Workaround: keep the external AuthURL (browser redirect), but force the TokenURL
	// to use the discovery host/scheme while preserving the advertised path.
	if discoveryURL != "" {
		if base, err := url.Parse(providerURL); err == nil && base.Scheme == "http" && base.Host != "" {
			if token, err := url.Parse(endpoint.TokenURL); err == nil && token.Path != "" {
				// Use the discovery host/scheme, but keep the token endpoint path as
				// advertised by the provider.
				base.Path = token.Path
				base.RawQuery = token.RawQuery
				endpoint.TokenURL = base.String()
			}
		}
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  cfg.OIDC.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	// Like TokenURL rewriting above, prefer fetching JWKS from the discovery host
	// when the external issuer hostname is not directly trusted/valid inside the
	// cluster (e.g. QA using a wildcard/prod cert).
	if discoveryURL != "" {
		if base, err := url.Parse(providerURL); err == nil && base.Scheme == "http" && base.Host != "" {
			jwksURL := strings.TrimRight(providerURL, "/") + "/keys"
			keySet := oidc.NewRemoteKeySet(context.Background(), jwksURL)
			verifier = oidc.NewVerifier(cfg.OIDC.IssuerURL, keySet, &oidc.Config{ClientID: cfg.OIDC.ClientID})
		}
	}

	return &OIDCClient{
		oauth2Config: oauth2Config,
		verifier:     verifier,
	}, nil
}

// OIDCLogin starts the Dex OIDC auth flow and stores state/nonce cookies.
//
//encore:api public raw method=GET path=/api/oidc/login
func (s *Service) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "OIDC not configured", http.StatusNotFound)
		return
	}

	next := sanitizeOIDCNext(r.URL.Query().Get("next"))
	state, err := randomOIDCString(32)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	nonce, err := randomOIDCString(32)
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	secure := s.sessionManager.cookieSecure(r)
	setOIDCCookie(w, s.sessionManager, oidcStateCookie, state, secure)
	setOIDCCookie(w, s.sessionManager, oidcNonceCookie, nonce, secure)
	setOIDCCookie(w, s.sessionManager, oidcNextCookie, url.QueryEscape(next), secure)

	authURL := s.oidc.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OIDCLoginAlias provides backward-compatible routing for legacy OIDC login URLs.
//
//encore:api public raw method=GET path=/api/skyforge/api/oidc/login
func (s *Service) OIDCLoginAlias(w http.ResponseWriter, r *http.Request) {
	s.OIDCLogin(w, r)
}

// OIDCCallback finishes the OIDC flow and issues the Skyforge session cookie.
//
//encore:api public raw method=GET path=/api/oidc/callback
func (s *Service) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "OIDC not configured", http.StatusNotFound)
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		http.Error(w, "missing oidc parameters", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != state {
		http.Error(w, "invalid oidc state", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil || nonceCookie.Value == "" {
		http.Error(w, "missing oidc nonce", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	token, err := s.oidc.oauth2Config.Exchange(ctx, code)
	if err != nil {
		rlog.Error("oidc exchange failed", "error", err)
		http.Error(w, "oidc exchange failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "missing id token", http.StatusUnauthorized)
		return
	}

	idToken, err := s.oidc.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		rlog.Error("invalid id token", "error", err)
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}
	if strings.TrimSpace(idToken.Nonce) == "" || idToken.Nonce != nonceCookie.Value {
		http.Error(w, "invalid oidc nonce", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse id token", http.StatusUnauthorized)
		return
	}

	username := strings.TrimSpace(claims.PreferredUsername)
	if username == "" && strings.Contains(claims.Email, "@") {
		username = strings.TrimSpace(strings.SplitN(claims.Email, "@", 2)[0])
	}
	if username == "" {
		username = strings.TrimSpace(idToken.Subject)
	}
	if username == "" {
		http.Error(w, "missing username", http.StatusUnauthorized)
		return
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" {
		if domain := strings.TrimSpace(s.cfg.CorpEmailDomain); domain != "" {
			email = username + "@" + domain
		}
	}
	displayName := strings.TrimSpace(claims.Name)
	if displayName == "" {
		displayName = username
	}

	profile := &UserProfile{
		Authenticated: true,
		Username:      username,
		DisplayName:   displayName,
		Email:         email,
		Groups:        claims.Groups,
		IsAdmin:       isAdminUser(s.cfg, username),
	}

	cookie, err := s.sessionManager.IssueCookieForHeaders(r.Header, profile)
	if err != nil {
		http.Error(w, "failed to issue session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	clearOIDCCookie(w, s.sessionManager, oidcStateCookie)
	clearOIDCCookie(w, s.sessionManager, oidcNonceCookie)

	next := "/"
	if nextCookie, err := r.Cookie(oidcNextCookie); err == nil && nextCookie.Value != "" {
		if decoded, err := url.QueryUnescape(nextCookie.Value); err == nil {
			next = sanitizeOIDCNext(decoded)
		}
	}
	clearOIDCCookie(w, s.sessionManager, oidcNextCookie)

	if err := s.userStore.upsert(profile.Username); err != nil {
		rlog.Warn("user store upsert failed", "error", err)
	}
	if s.db != nil {
		writeAuditEvent(ctx, s.db, profile.Username, profile.IsAdmin, "", "auth.login", "", auditDetailsFromEncore(encore.CurrentRequest()))
	}

	http.Redirect(w, r, next, http.StatusFound)
}

// OIDCCallbackAlias provides backward-compatible routing for legacy OIDC callback URLs.
//
//encore:api public raw method=GET path=/api/skyforge/api/oidc/callback
func (s *Service) OIDCCallbackAlias(w http.ResponseWriter, r *http.Request) {
	s.OIDCCallback(w, r)
}

func sanitizeOIDCNext(raw string) string {
	next := strings.TrimSpace(raw)
	if next == "" {
		return "/"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "://") {
		return "/"
	}
	return next
}

func randomOIDCString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setOIDCCookie(w http.ResponseWriter, sm *SessionManager, name, value string, secure bool) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((10 * time.Minute).Seconds()),
	}
	if sm.cookieDomain != "" {
		cookie.Domain = sm.cookieDomain
	}
	http.SetCookie(w, cookie)
}

func clearOIDCCookie(w http.ResponseWriter, sm *SessionManager, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	if sm.cookieDomain != "" {
		cookie.Domain = sm.cookieDomain
	}
	http.SetCookie(w, cookie)
}
