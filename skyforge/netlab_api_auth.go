package skyforge

import (
	"fmt"
	"net/http"
	"strings"
)

type netlabAPIAuth struct {
	BearerToken   string
	BasicUsername string
	BasicPassword string
}

func (a netlabAPIAuth) apply(req *http.Request) {
	if req == nil {
		return
	}
	if token := strings.TrimSpace(a.BearerToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		return
	}
	username := strings.TrimSpace(a.BasicUsername)
	if username == "" {
		return
	}
	if strings.TrimSpace(a.BasicPassword) == "" {
		return
	}
	req.SetBasicAuth(username, a.BasicPassword)
}

func (s *Service) netlabAPIAuthForUser(username string, server NetlabServerConfig) (netlabAPIAuth, error) {
	if token := strings.TrimSpace(server.APIToken); token != "" {
		return netlabAPIAuth{BearerToken: token}, nil
	}
	if s != nil && s.db != nil {
		if cached, ok := getCachedLDAPPassword(s.db, strings.TrimSpace(username)); ok {
			cached = strings.TrimSpace(cached)
			if cached != "" {
				return netlabAPIAuth{
					BasicUsername: strings.TrimSpace(username),
					BasicPassword: cached,
				}, nil
			}
		}
	}
	return netlabAPIAuth{}, fmt.Errorf("netlab credentials are required (login again to refresh cached password)")
}
