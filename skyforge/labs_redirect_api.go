package skyforge

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"encore.dev/beta/errs"
)

type LabsRedirectParams struct {
	EveServer   string
	WorkspaceID string
}

// LabsRedirect resolves the configured labs UI redirect.
//
//encore:api public raw method=GET path=/labs
func (s *Service) LabsRedirect(w http.ResponseWriter, req *http.Request) {
	s.labsRedirect(w, req)
}

// LabsRedirectAny handles subpaths under /labs.
//
//encore:api public raw method=GET path=/labs/*rest
func (s *Service) LabsRedirectAny(w http.ResponseWriter, req *http.Request) {
	s.labsRedirect(w, req)
}

func (s *Service) labsRedirect(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/labs")
	if rest != "" && rest != "/" {
		s.proxyEveLab(w, req)
		return
	}

	params := &LabsRedirectParams{
		EveServer:   strings.TrimSpace(req.URL.Query().Get("eve_server")),
		WorkspaceID: strings.TrimSpace(req.URL.Query().Get("workspace_id")),
	}
	location, err := s.resolveLabsRedirect(params)
	if err != nil {
		errs.HTTPError(w, err)
		return
	}
	http.Redirect(w, req, location, http.StatusFound)
}

func (s *Service) resolveLabsRedirect(params *LabsRedirectParams) (string, error) {
	targetName := ""
	workspaceID := ""
	if params != nil {
		targetName = strings.TrimSpace(params.EveServer)
		workspaceID = strings.TrimSpace(params.WorkspaceID)
	}
	server, err := s.selectEveServer(targetName, workspaceID)
	if err != nil {
		return "", err
	}
	target := strings.TrimSpace(server.Name)
	if target == "" {
		target = "eve-default"
	}
	return "/api/skyforge/api/eve/sso?server=" + url.QueryEscape(target), nil
}

func (s *Service) proxyEveLab(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/labs/")
	if rest == "" {
		http.NotFound(w, req)
		return
	}

	parts := strings.SplitN(rest, "/", 2)
	serverName := strings.TrimSpace(parts[0])
	if serverName == "" {
		http.NotFound(w, req)
		return
	}
	pathSuffix := "/"
	if len(parts) > 1 {
		pathSuffix += parts[1]
	}

	server, err := s.selectEveServer(serverName, "")
	if err != nil {
		errs.HTTPError(w, err)
		return
	}

	base := strings.TrimRight(strings.TrimSpace(server.APIURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(server.WebURL), "/")
	}
	if base == "" && strings.TrimSpace(server.SSHHost) != "" {
		base = "https://" + strings.TrimSpace(server.SSHHost)
	}
	if base == "" {
		http.Error(w, "eve-ng url is not configured", http.StatusBadGateway)
		return
	}

	targetURL, err := url.Parse(base)
	if err != nil {
		http.Error(w, "invalid eve-ng url", http.StatusBadGateway)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)
		r.URL.Path = pathSuffix
		r.URL.RawPath = pathSuffix
		r.Host = targetURL.Host
	}
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: server.SkipTLSVerify},
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil
		}
		if strings.HasPrefix(location, "/") {
			resp.Header.Set("Location", "/labs/"+serverName+location)
			return nil
		}
		loc, err := url.Parse(location)
		if err != nil || !strings.EqualFold(loc.Host, targetURL.Host) {
			return nil
		}
		rewrite := "/labs/" + serverName + loc.Path
		if loc.RawQuery != "" {
			rewrite += "?" + loc.RawQuery
		}
		resp.Header.Set("Location", rewrite)
		return nil
	}

	proxy.ServeHTTP(w, req)
}

func (s *Service) selectEveServer(targetName, workspaceID string) (*EveServerConfig, error) {
	targetName = strings.TrimSpace(targetName)
	workspaceID = strings.TrimSpace(workspaceID)
	if targetName == "" && workspaceID != "" {
		if workspaces, err := s.workspaceStore.load(); err == nil {
			if workspace := findWorkspaceByKey(workspaces, workspaceID); workspace != nil && strings.TrimSpace(workspace.EveServer) != "" {
				targetName = strings.TrimSpace(workspace.EveServer)
			}
		}
	}

	var selected *EveServerConfig
	for i := range s.cfg.EveServers {
		server := &s.cfg.EveServers[i]
		if targetName == "" || strings.EqualFold(server.Name, targetName) {
			selected = server
			break
		}
	}
	if selected == nil && s.cfg.Labs.EveAPIURL != "" {
		selected = &EveServerConfig{
			Name:          "eve-default",
			APIURL:        s.cfg.Labs.EveAPIURL,
			SkipTLSVerify: s.cfg.Labs.EveSkipTLSVerify,
		}
	}
	if selected == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("no eve-ng servers configured").Err()
	}

	server := normalizeEveServer(*selected, s.cfg.Labs)
	return &server, nil
}
