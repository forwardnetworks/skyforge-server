package skyforge

import (
	"net/http"
	"net/url"
	"strings"
)

func corporateEmailForUser(cfg Config, username string) string {
	username = strings.TrimSpace(username)
	if username == "" {
		return ""
	}
	if strings.Contains(username, "@") {
		return username
	}
	domain := strings.TrimSpace(cfg.CorpEmailDomain)
	if domain == "" {
		return ""
	}
	return username + "@" + domain
}

// AzurePortalRedirect opens the Azure portal with a login hint.
//
//encore:api auth raw method=GET path=/api/azure/portal
func (s *Service) AzurePortalRedirect(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	email := corporateEmailForUser(s.cfg, user.Username)
	target := "https://portal.azure.com/"
	if email != "" {
		q := url.Values{}
		q.Set("login_hint", email)
		target = target + "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// GCPConsoleRedirect opens the GCP console with a login hint.
//
//encore:api auth raw method=GET path=/api/gcp/console
func (s *Service) GCPConsoleRedirect(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	email := corporateEmailForUser(s.cfg, user.Username)
	target := "https://console.cloud.google.com/"
	if email != "" {
		q := url.Values{}
		q.Set("authuser", email)
		target = target + "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}
