package taskengine

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
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

func (e *Engine) netlabAPIAuthForUser(username string, server NetlabServerConfig) (netlabAPIAuth, error) {
	if token := strings.TrimSpace(server.APIToken); token != "" {
		return netlabAPIAuth{BearerToken: token}, nil
	}
	if e != nil && e.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		pw, ok := getCachedLDAPPassword(ctx, e.db, e.box, strings.TrimSpace(username))
		cancel()
		if ok {
			return netlabAPIAuth{
				BasicUsername: strings.TrimSpace(username),
				BasicPassword: pw,
			}, nil
		}
	}
	return netlabAPIAuth{}, fmt.Errorf("netlab credentials are required (login again to refresh cached password)")
}
