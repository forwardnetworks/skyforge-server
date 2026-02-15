package skyforge

import (
	"net/http"
	"strings"
)

func userScopeAliasTarget(req *http.Request) string {
	rest := strings.TrimPrefix(req.URL.Path, "/api/user/workspace")
	if rest == req.URL.Path {
		rest = strings.TrimPrefix(req.URL.Path, "/api/user/scope")
	}
	if rest == "" {
		rest = "/"
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	target := "/api/workspaces/me" + rest
	if strings.TrimSpace(req.URL.RawQuery) != "" {
		target += "?" + req.URL.RawQuery
	}
	return target
}

func (s *Service) userScopeAlias(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, userScopeAliasTarget(req), http.StatusTemporaryRedirect)
}

func (s *Service) deprecatedUserScopeAlias(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Sunset", "Fri, 15 May 2026 00:00:00 GMT")
	w.Header().Add("Link", "</api/user/workspace>; rel=\"successor-version\"")
	w.Header().Add("Warning", "299 - \"Deprecated API path; use /api/user/workspace/*\"")
	s.userScopeAlias(w, req)
}

// UserWorkspaceAlias (GET)
//
//encore:api auth raw method=GET path=/api/user/workspace/*rest
func (s *Service) UserWorkspaceAlias(w http.ResponseWriter, req *http.Request) {
	s.userScopeAlias(w, req)
}

//encore:api auth raw method=POST path=/api/user/workspace/*rest
func (s *Service) UserWorkspaceAliasPost(w http.ResponseWriter, req *http.Request) {
	s.userScopeAlias(w, req)
}

//encore:api auth raw method=PUT path=/api/user/workspace/*rest
func (s *Service) UserWorkspaceAliasPut(w http.ResponseWriter, req *http.Request) {
	s.userScopeAlias(w, req)
}

//encore:api auth raw method=DELETE path=/api/user/workspace/*rest
func (s *Service) UserWorkspaceAliasDelete(w http.ResponseWriter, req *http.Request) {
	s.userScopeAlias(w, req)
}

//encore:api auth raw method=PATCH path=/api/user/workspace/*rest
func (s *Service) UserWorkspaceAliasPatch(w http.ResponseWriter, req *http.Request) {
	s.userScopeAlias(w, req)
}

// UserScopeAlias (GET)
//
//encore:api auth raw method=GET path=/api/user/scope/*rest
func (s *Service) UserScopeAlias(w http.ResponseWriter, req *http.Request) {
	s.deprecatedUserScopeAlias(w, req)
}

//encore:api auth raw method=POST path=/api/user/scope/*rest
func (s *Service) UserScopeAliasPost(w http.ResponseWriter, req *http.Request) {
	s.deprecatedUserScopeAlias(w, req)
}

//encore:api auth raw method=PUT path=/api/user/scope/*rest
func (s *Service) UserScopeAliasPut(w http.ResponseWriter, req *http.Request) {
	s.deprecatedUserScopeAlias(w, req)
}

//encore:api auth raw method=DELETE path=/api/user/scope/*rest
func (s *Service) UserScopeAliasDelete(w http.ResponseWriter, req *http.Request) {
	s.deprecatedUserScopeAlias(w, req)
}

//encore:api auth raw method=PATCH path=/api/user/scope/*rest
func (s *Service) UserScopeAliasPatch(w http.ResponseWriter, req *http.Request) {
	s.deprecatedUserScopeAlias(w, req)
}
