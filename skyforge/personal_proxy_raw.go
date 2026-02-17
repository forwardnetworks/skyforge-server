package skyforge

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"encore.dev/rlog"
)

const personalProxyPrefix = "/api/personal"

func personalProxyTarget() (*url.URL, error) {
	// Skyforge server listens on 8085 in-cluster.
	return url.Parse("http://127.0.0.1:8085")
}

func personalProxyPath(reqPath string) string {
	p := strings.TrimSpace(reqPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasPrefix(p, personalProxyPrefix) {
		p = strings.TrimPrefix(p, personalProxyPrefix)
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func (s *Service) personalProxyRaw(w http.ResponseWriter, req *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	pc, err := s.userContextForCurrentUser(req.Context(), user)
	if err != nil || pc == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("user context not found\n"))
		return
	}

	target, err := personalProxyTarget()
	if err != nil {
		rlog.Error("user proxy target invalid", "err", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	suffix := personalProxyPath(req.URL.Path)
	if suffix == "/" {
		suffix = ""
	}
	upPath := "/api/user-contexts/" + url.PathEscape(pc.userContext.ID) + suffix
	upQuery := ""
	if req.URL != nil {
		upQuery = req.URL.RawQuery
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		if origDirector != nil {
			origDirector(r)
		}
		r.URL.Path = upPath
		r.URL.RawPath = ""
		r.URL.RawQuery = upQuery
		r.Host = target.Host
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, e error) {
		rlog.Warn("user proxy upstream error", "err", e)
		rw.WriteHeader(http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, req)
}

//encore:api auth raw method=GET path=/api/personal/*rest
func (s *Service) PersonalProxyGET(w http.ResponseWriter, req *http.Request) {
	s.personalProxyRaw(w, req)
}

//encore:api auth raw method=POST path=/api/personal/*rest
func (s *Service) PersonalProxyPOST(w http.ResponseWriter, req *http.Request) {
	s.personalProxyRaw(w, req)
}

//encore:api auth raw method=PUT path=/api/personal/*rest
func (s *Service) PersonalProxyPUT(w http.ResponseWriter, req *http.Request) {
	s.personalProxyRaw(w, req)
}

//encore:api auth raw method=DELETE path=/api/personal/*rest
func (s *Service) PersonalProxyDELETE(w http.ResponseWriter, req *http.Request) {
	s.personalProxyRaw(w, req)
}

//encore:api auth raw method=PATCH path=/api/personal/*rest
func (s *Service) PersonalProxyPATCH(w http.ResponseWriter, req *http.Request) {
	s.personalProxyRaw(w, req)
}
