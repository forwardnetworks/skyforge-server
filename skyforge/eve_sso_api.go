package skyforge

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type eveLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// EveSSO logs into the selected EVE-NG server using the cached LDAP password
// and redirects to the proxied /labs/<server>/ path.
//
//encore:api auth raw method=GET path=/api/eve/sso
func (s *Service) EveSSO(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		s.redirectToReauth(w, r)
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("server"))
	server, err := s.selectEveServer(target, "")
	if err != nil {
		errs.HTTPError(w, err)
		return
	}
	target = strings.TrimSpace(server.Name)
	if target == "" {
		target = "eve-default"
	}

	base := strings.TrimRight(strings.TrimSpace(server.APIURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(server.WebURL), "/")
	}
	if base == "" && strings.TrimSpace(server.SSHHost) != "" {
		base = "https://" + strings.TrimSpace(server.SSHHost)
	}
	if base == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "eve-ng url is not configured"})
		return
	}

	password, ok := getCachedLDAPPassword(s.db, user.Username)
	loginUser := user.Username
	if !ok {
		serverUser := strings.TrimSpace(server.Username)
		serverPass := strings.TrimSpace(server.Password)
		if serverUser != "" && serverPass != "" {
			loginUser = serverUser
			password = serverPass
		} else {
			s.redirectToReauth(w, r)
			return
		}
	}

	loginURL := base + "/api/auth/login"
	payload := eveLoginRequest{Username: loginUser, Password: password}
	body, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to build login request"})
		return
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: server.SkipTLSVerify},
		},
	}
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to reach eve-ng"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "eve-ng login failed"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "eve-ng login rejected"})
		return
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "eve-ng login missing cookies"})
		return
	}

	cookiePath := "/labs/" + url.PathEscape(target)
	forwardedProto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if forwardedProto == "" && r.TLS != nil {
		forwardedProto = "https"
	}
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		c.Domain = ""
		c.Path = cookiePath
		if forwardedProto == "https" {
			c.Secure = true
		}
		http.SetCookie(w, c)
	}

	labPath := strings.TrimSpace(r.URL.Query().Get("lab"))
	if labPath == "" {
		labPath = strings.TrimSpace(r.URL.Query().Get("path"))
	}
	redirectPath := cookiePath + "/"
	if labPath != "" {
		redirectPath = fmt.Sprintf("%s/#/lab?path=%s", cookiePath, url.QueryEscape(labPath))
	}

	http.Redirect(w, r, redirectPath, http.StatusFound)
}
