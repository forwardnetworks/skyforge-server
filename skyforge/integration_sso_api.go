package skyforge

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type yaadeLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

	// Never proxy in-cluster service calls through environment proxies.
	// Some clusters set HTTP(S)_PROXY for egress which can break service DNS.
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
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

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		log.Printf("yaade sso: missing session cookie from login")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "api testing login failed"})
		return
	}

	secure := strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil
	for _, c := range cookies {
		if c == nil || c.Name == "" || c.Value == "" {
			continue
		}
		http.SetCookie(w, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	http.Redirect(w, r, "/api-testing/", http.StatusFound)
}

// GiteaPublicSSO logs into Gitea with a read-only public account.
//
//encore:api public raw method=GET path=/api/gitea/public
func (s *Service) GiteaPublicSSO(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/git/", http.StatusFound)
}
