package skyforge

import (
	"net/http"
	"strings"
)

const defaultCoderLaunchPath = "/coder/"

func sanitizeCoderLaunchPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return defaultCoderLaunchPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Keep launch redirects under the Coder routed prefix on the shared hostname.
	if !strings.HasPrefix(path, "/coder") {
		return defaultCoderLaunchPath
	}
	return path
}

// CoderLaunch redirects authenticated users to the configured Coder landing page.
//
//encore:api auth raw method=GET path=/api/coder/launch
func (s *Service) CoderLaunch(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Features.CoderEnabled {
		http.NotFound(w, r)
		return
	}
	if _, err := requireAuthUser(); err != nil {
		s.redirectToReauth(w, r)
		return
	}

	target := sanitizeCoderLaunchPath(s.cfg.Coder.PortalRedirectPath)
	if next := strings.TrimSpace(r.URL.Query().Get("next")); next != "" {
		target = sanitizeCoderLaunchPath(next)
	}
	http.Redirect(w, r, target, http.StatusFound)
}
