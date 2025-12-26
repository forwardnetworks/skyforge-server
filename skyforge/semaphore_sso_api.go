package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type SemaphoreSSOResponse struct {
	Status string `json:"status"`
}

// SemaphoreSSO performs a one-time token exchange for Semaphore and redirects to the UI.
//
//encore:api auth raw method=GET path=/api/semaphore/sso
func (s *Service) SemaphoreSSO(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	password, ok := getCachedLDAPPassword(user.Username)
	if !ok {
		writeJSON(w, http.StatusPreconditionFailed, map[string]string{"error": "LDAP password unavailable; reauthenticate"})
		return
	}

	semURL := strings.TrimRight(strings.TrimSpace(s.cfg.SemaphoreURL), "/")
	// Config is typically http://semaphore:3000/api, but the UI/API are served under /semaphore/.
	// Prefer the /semaphore/api path and fall back to /api for older configs.
	semBase := semURL
	if strings.HasSuffix(semBase, "/api") {
		semBase = strings.TrimSuffix(semBase, "/api")
	}
	loginCandidates := []string{
		semBase + "/semaphore/api/auth/login",
		semBase + "/api/auth/login",
	}
	if strings.Contains(semURL, "/semaphore/api") {
		loginCandidates = []string{semURL + "/auth/login", semBase + "/semaphore/api/auth/login", semBase + "/api/auth/login"}
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 15 * time.Second, Jar: jar}
	payload := map[string]any{
		"auth":     user.Username,
		"password": password,
	}
	body, _ := json.Marshal(payload)
	var resp *http.Response
	for _, loginURL := range loginCandidates {
		req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		tryResp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = tryResp.Body.Close()
		ct := strings.ToLower(strings.TrimSpace(tryResp.Header.Get("Content-Type")))
		// Some base paths serve the UI index.html at /api/auth/login (200 text/html); ignore that.
		if strings.HasPrefix(ct, "text/html") {
			continue
		}
		if tryResp.StatusCode == http.StatusOK || tryResp.StatusCode == http.StatusNoContent {
			resp = tryResp
			break
		}
	}
	if resp == nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "semaphore login failed"})
		return
	}

	loginParsed, err := url.Parse(semBase + "/semaphore/")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid semaphore url"})
		return
	}
	forwardedProto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	secure := forwardedProto == "https" || r.TLS != nil
	// cookiejar only returns cookies matching the request path; collect cookies for both /semaphore and /api roots.
	rootParsed, _ := url.Parse(semBase + "/")
	apiParsed, _ := url.Parse(semBase + "/api/")
	candidates := []*http.Cookie{}
	candidates = append(candidates, jar.Cookies(loginParsed)...)
	if rootParsed != nil {
		candidates = append(candidates, jar.Cookies(rootParsed)...)
	}
	if apiParsed != nil {
		candidates = append(candidates, jar.Cookies(apiParsed)...)
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if c == nil || c.Name == "" {
			continue
		}
		key := c.Name + "=" + c.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		c.Path = "/semaphore"
		c.Domain = ""
		c.Secure = secure
		http.SetCookie(w, c)
	}

	next := strings.TrimSpace(r.URL.Query().Get("next"))
	if next == "" {
		next = "/semaphore/"
	}
	if strings.HasPrefix(next, "/semaphore") {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/semaphore/", http.StatusFound)
}

// SemaphoreSSOStatus verifies that the current user can perform SSO.
//
//encore:api auth method=GET path=/api/semaphore/sso/status
func (s *Service) SemaphoreSSOStatus(ctx context.Context) (*SemaphoreSSOResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if _, ok := getCachedLDAPPassword(user.Username); !ok {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("LDAP password unavailable; reauthenticate").Err()
	}
	return &SemaphoreSSOResponse{Status: "ready"}, nil
}
