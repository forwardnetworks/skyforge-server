package skyforge

import (
	"net/http"
	"net/url"
	"strings"
)

func (s *Service) clearSessionCookieForRequest(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.sessionManager == nil {
		return
	}
	name := strings.TrimSpace(s.sessionManager.cookieName)
	if name == "" {
		name = "skyforge_session"
	}

	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.sessionManager.cookieSecure(req),
	}
	if strings.TrimSpace(s.sessionManager.cookieDomain) != "" {
		c.Domain = strings.TrimSpace(s.sessionManager.cookieDomain)
	}
	http.SetCookie(w, c)
}

func (s *Service) integrationLogoutRedirect(w http.ResponseWriter, req *http.Request, next string) {
	s.clearSessionCookieForRequest(w, req)
	if strings.TrimSpace(next) == "" {
		next = "/"
	}
	http.Redirect(w, req, "/?next="+url.QueryEscape(next), http.StatusFound)
}

// NetboxLogout clears the Skyforge session cookie and redirects to the Skyforge landing page.
//
//encore:api public raw method=GET path=/netbox/logout
func (s *Service) NetboxLogout(w http.ResponseWriter, req *http.Request) {
	s.integrationLogoutRedirect(w, req, "/netbox/")
}

// NetboxLogoutSlash clears the Skyforge session cookie and redirects to the Skyforge landing page.
//
//encore:api public raw method=GET path=/netbox/logout/
func (s *Service) NetboxLogoutSlash(w http.ResponseWriter, req *http.Request) {
	s.integrationLogoutRedirect(w, req, "/netbox/")
}

// NautobotLogout clears the Skyforge session cookie and redirects to the Skyforge landing page.
//
//encore:api public raw method=GET path=/nautobot/logout
func (s *Service) NautobotLogout(w http.ResponseWriter, req *http.Request) {
	s.integrationLogoutRedirect(w, req, "/nautobot/")
}

// NautobotLogoutSlash clears the Skyforge session cookie and redirects to the Skyforge landing page.
//
//encore:api public raw method=GET path=/nautobot/logout/
func (s *Service) NautobotLogoutSlash(w http.ResponseWriter, req *http.Request) {
	s.integrationLogoutRedirect(w, req, "/nautobot/")
}

// LogoutAll clears the Skyforge cookie and redirects to the landing page (used for manual "reset").
//
//encore:api public raw method=GET path=/logout
func (s *Service) LogoutAll(w http.ResponseWriter, req *http.Request) {
	s.clearSessionCookieForRequest(w, req)
	http.Redirect(w, req, "/?next="+url.QueryEscape("/"), http.StatusFound)
}
