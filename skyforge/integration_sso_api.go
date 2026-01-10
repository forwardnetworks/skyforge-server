package skyforge

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var csrfInputRE = regexp.MustCompile(`name=["']([^"']+)["']\s+value=["']([^"']+)["']`)
var formActionRE = regexp.MustCompile(`(?is)<form[^>]*\saction=["']([^"']+)["']`)

func extractFormValue(html, field string) string {
	matches := csrfInputRE.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		if strings.EqualFold(m[1], field) {
			return m[2]
		}
	}
	return ""
}

func cookiePathForRedirect(redirectPath string) string {
	redirectPath = strings.TrimSpace(redirectPath)
	if redirectPath == "" || !strings.HasPrefix(redirectPath, "/") {
		return "/"
	}
	trimmed := strings.TrimPrefix(redirectPath, "/")
	if trimmed == "" {
		return "/"
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "/"
	}
	return "/" + parts[0]
}

type yaadeLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func extractFormAction(html string) string {
	m := formActionRE.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func buildActionURL(base *url.URL, action string, fallback string) string {
	action = strings.TrimSpace(action)
	if action == "" {
		return fallback
	}
	parsed, err := url.Parse(action)
	if err != nil {
		return fallback
	}
	if parsed.IsAbs() {
		return parsed.String()
	}
	if base == nil {
		return fallback
	}
	return base.ResolveReference(parsed).String()
}

func performFormSSO(w http.ResponseWriter, r *http.Request, targetBase, loginPath, redirectPath, userField, passField, csrfField, forwardedProto, forwardedHost, username, password string) {
	base := strings.TrimRight(strings.TrimSpace(targetBase), "/")
	if base == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "integration not configured"})
		return
	}

	cookiePath := cookiePathForRedirect(redirectPath)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 15 * time.Second, Jar: jar}
	postClient := &http.Client{
		Timeout:       15 * time.Second,
		Jar:           jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	loginURL := base + loginPath

	getReq, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		log.Printf("sso: failed to build login request url=%q err=%v", loginURL, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to reach integration login"})
		return
	}
	if forwardedProto != "" {
		getReq.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	if forwardedHost != "" {
		getReq.Host = forwardedHost
		getReq.Header.Set("X-Forwarded-Host", forwardedHost)
	}
	getResp, err := client.Do(getReq)
	if err != nil {
		log.Printf("sso: login GET failed url=%q err=%v", loginURL, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to reach integration login"})
		return
	}
	respCookies := getResp.Cookies()
	bodyBytes, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode >= 400 {
		log.Printf("sso: login GET rejected url=%q status=%d", loginURL, getResp.StatusCode)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to reach integration login"})
		return
	}

	// If the integration is served behind a path prefix (e.g. /git), the login endpoint may redirect.
	// Use the final URL for the POST and for referer/origin headers.
	finalLoginURL := loginURL
	if getResp.Request != nil && getResp.Request.URL != nil && strings.TrimSpace(getResp.Request.URL.String()) != "" {
		finalLoginURL = getResp.Request.URL.String()
	}
	baseURL := getResp.Request.URL
	action := extractFormAction(string(bodyBytes))
	if cookiePath != "/" && strings.HasPrefix(action, cookiePath+"/") && baseURL != nil && !strings.HasPrefix(baseURL.Path, cookiePath) {
		action = strings.TrimPrefix(action, cookiePath)
		if !strings.HasPrefix(action, "/") {
			action = "/" + action
		}
	}
	postURL := buildActionURL(baseURL, action, finalLoginURL)

	form := url.Values{}
	form.Set(userField, username)
	form.Set(passField, password)
	if csrfField != "" {
		if token := extractFormValue(string(bodyBytes), csrfField); token != "" {
			form.Set(csrfField, token)
		}
	}

	postReq, err := http.NewRequest(http.MethodPost, postURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		log.Printf("sso: failed to build login POST url=%q err=%v", postURL, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to build integration login"})
		return
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	referer := postURL
	origin := ""
	if forwardedProto != "" {
		if parsed, err := url.Parse(postURL); err == nil {
			parsed.Scheme = forwardedProto
			referer = parsed.String()
			if parsed.Host != "" {
				origin = parsed.Scheme + "://" + parsed.Host
			}
		}
		postReq.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	if forwardedHost != "" {
		if parsed, err := url.Parse(referer); err == nil {
			parsed.Host = forwardedHost
			if parsed.Scheme == "" {
				parsed.Scheme = forwardedProto
			}
			referer = parsed.String()
		}
		postReq.Host = forwardedHost
		postReq.Header.Set("X-Forwarded-Host", forwardedHost)
		if forwardedProto == "" {
			forwardedProto = "https"
		}
		origin = forwardedProto + "://" + forwardedHost
	}
	postReq.Header.Set("Referer", referer)
	if origin != "" {
		postReq.Header.Set("Origin", origin)
	}
	if len(respCookies) > 0 {
		postReq.Header.Set("Cookie", joinCookieHeader(respCookies))
	}

	postResp, err := postClient.Do(postReq)
	if err != nil {
		log.Printf("sso: login POST failed url=%q err=%v", loginURL, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "integration login failed"})
		return
	}
	postCookies := postResp.Cookies()
	if postResp.StatusCode >= 400 {
		log.Printf("sso: login POST rejected url=%q status=%d location=%q", postURL, postResp.StatusCode, postResp.Header.Get("Location"))
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "integration login rejected"})
		return
	}
	if postResp.StatusCode >= 200 && postResp.StatusCode < 300 {
		log.Printf("sso: login POST did not redirect url=%q status=%d", postURL, postResp.StatusCode)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "integration login rejected"})
		return
	}

	parsed, err := url.Parse(base)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid integration url"})
		return
	}
	// cookiejar only returns cookies matching the request path. Consider both "/" and the target path.
	cookieURL := *parsed
	cookieURL.Path = cookiePath
	candidates := make([]*http.Cookie, 0, len(respCookies)+len(postCookies)+8)
	candidates = append(candidates, respCookies...)
	candidates = append(candidates, postCookies...)
	candidates = append(candidates, jar.Cookies(&cookieURL)...)
	candidates = append(candidates, jar.Cookies(parsed)...)
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
		c.Domain = ""
		c.Path = cookiePath
		if forwardedProto == "https" {
			c.Secure = true
		}
		http.SetCookie(w, c)
	}

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func ssoBaseURLOrDefault(baseURL string, fallback string) string {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		return strings.TrimSpace(fallback)
	}
	return base
}

func joinCookieHeader(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func (s *Service) redirectToReauth(w http.ResponseWriter, r *http.Request) {
	const publicAPIPrefix = "/api/skyforge"
	requestURI := strings.TrimSpace(r.URL.RequestURI())
	if requestURI == "" {
		requestURI = "/"
	}
	externalNext := publicAPIPrefix + requestURI
	if s != nil && s.oidc != nil {
		http.Redirect(
			w,
			r,
			publicAPIPrefix+"/api/oidc/login?next="+url.QueryEscape(externalNext),
			http.StatusFound,
		)
		return
	}
	http.Redirect(
		w,
		r,
		publicAPIPrefix+"/api/reauth?next="+url.QueryEscape(externalNext),
		http.StatusFound,
	)
}

func normalizeGiteaBaseURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return base
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	path := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(strings.ToLower(path), "/git") || strings.EqualFold(path, "/git") {
		path = strings.TrimSuffix(path, "/git")
		parsed.Path = path
		parsed.RawPath = ""
	}
	return strings.TrimRight(parsed.String(), "/")
}

// GiteaSSO performs a one-time token exchange for Gitea and redirects to the UI.
//
//encore:api auth raw method=GET path=/api/gitea/sso
func (s *Service) GiteaSSO(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		s.redirectToReauth(w, r)
		return
	}
	next := strings.TrimSpace(r.URL.Query().Get("next"))
	if next == "" || !strings.HasPrefix(next, "/git") {
		next = "/git/"
	}
	if s.oidc != nil {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	password, ok := getCachedLDAPPassword(user.Username)
	if !ok {
		s.redirectToReauth(w, r)
		return
	}
	if err := ensureGiteaUserPassword(s.cfg, user.Username, user.DisplayName, user.Email, password); err != nil {
		log.Printf("gitea sso: failed to sync user password for %s: %v", user.Username, err)
	}

	forwardedProto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if forwardedProto == "" && r.TLS != nil {
		forwardedProto = "https"
	}
	forwardedHost := strings.TrimSpace(r.Host)
	baseURL := giteaInternalBaseURL(s.cfg)
	if baseURL == "" {
		baseURL = normalizeGiteaBaseURL(s.cfg.GiteaBaseURL)
	}
	performFormSSO(
		w,
		r,
		baseURL,
		"/user/login",
		next,
		"user_name",
		"password",
		"_csrf",
		forwardedProto,
		forwardedHost,
		user.Username,
		password,
	)
}

// NetboxSSO performs a one-time token exchange for NetBox and redirects to the UI.
//
//encore:api auth raw method=GET path=/api/netbox/sso
func (s *Service) NetboxSSO(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		s.redirectToReauth(w, r)
		return
	}
	if s.oidc != nil {
		http.Redirect(w, r, "/netbox/", http.StatusFound)
		return
	}
	password, ok := getCachedLDAPPassword(user.Username)
	loginUser := user.Username
	if !ok {
		s.redirectToReauth(w, r)
		return
	}
	performFormSSO(
		w,
		r,
		netboxInternalBaseURL(s.cfg),
		"/login/",
		"/netbox/",
		"username",
		"password",
		"csrfmiddlewaretoken",
		"https",
		"",
		loginUser,
		password,
	)
}

// NautobotSSO performs a one-time token exchange for Nautobot and redirects to the UI.
//
//encore:api auth raw method=GET path=/api/nautobot/sso
func (s *Service) NautobotSSO(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		s.redirectToReauth(w, r)
		return
	}
	if s.oidc != nil {
		http.Redirect(w, r, "/nautobot/", http.StatusFound)
		return
	}
	password, ok := getCachedLDAPPassword(user.Username)
	loginUser := user.Username
	if !ok {
		s.redirectToReauth(w, r)
		return
	}
	performFormSSO(
		w,
		r,
		nautobotInternalBaseURL(s.cfg),
		"/login/",
		"/nautobot/",
		"username",
		"password",
		"csrfmiddlewaretoken",
		"https",
		"",
		loginUser,
		password,
	)
}

// YaadeSSO performs a one-time login against Yaade using the shared admin account
// and redirects to the API testing UI.
//
//encore:api auth raw method=GET path=/api/yaade/sso
func (s *Service) YaadeSSO(w http.ResponseWriter, r *http.Request) {
	_, err := requireAuthUser()
	if err != nil {
		s.redirectToReauth(w, r)
		return
	}
	adminUser := strings.TrimSpace(s.cfg.YaadeAdminUsername)
	adminPass := strings.TrimSpace(s.cfg.YaadeAdminPassword)
	if adminUser == "" || adminPass == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "yaade admin credentials not configured"})
		return
	}

	base := strings.TrimRight(yaadeInternalBaseURL(s.cfg), "/")
	if base == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "yaade not configured"})
		return
	}

	payload := yaadeLoginPayload{Username: adminUser, Password: adminPass}
	body, _ := json.Marshal(payload)
	loginURL := base + "/api-testing/api/login"
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("yaade sso: failed to build login request: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to reach api testing login"})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("yaade sso: login failed url=%q err=%v", loginURL, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to reach api testing login"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("yaade sso: login rejected url=%q status=%d", loginURL, resp.StatusCode)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "api testing login rejected"})
		return
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "vertx-web.session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		log.Printf("yaade sso: missing session cookie from login")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "api testing login failed"})
		return
	}

	secure := strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie.Name,
		Value:    sessionCookie.Value,
		Path:     "/api-testing",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/api-testing/", http.StatusFound)
}

// GiteaPublicSSO logs into Gitea with a read-only public account.
//
//encore:api public raw method=GET path=/api/gitea/public
func (s *Service) GiteaPublicSSO(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/git/", http.StatusFound)
}
