package skyforge

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

type LabsRedirectParams struct {
	EveServer string
	ProjectID string
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
	params := &LabsRedirectParams{
		EveServer: strings.TrimSpace(req.URL.Query().Get("eve_server")),
		ProjectID: strings.TrimSpace(req.URL.Query().Get("project_id")),
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
	projectID := ""
	if params != nil {
		targetName = strings.TrimSpace(params.EveServer)
		projectID = strings.TrimSpace(params.ProjectID)
	}
	if targetName == "" && projectID != "" {
		if pid, err := strconv.Atoi(projectID); err == nil && pid > 0 {
			if projects, err := s.projectStore.load(); err == nil {
				for _, p := range projects {
					if p.SemaphoreProjectID == pid && strings.TrimSpace(p.EveServer) != "" {
						targetName = strings.TrimSpace(p.EveServer)
						break
					}
				}
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
		return "", errs.B().Code(errs.Unavailable).Msg("no eve-ng servers configured").Err()
	}

	server := normalizeEveServer(*selected, s.cfg.Labs)
	web := strings.TrimSpace(server.WebURL)
	if web == "" {
		web = strings.TrimSpace(server.APIURL)
	}
	if web == "" && strings.TrimSpace(server.SSHHost) != "" {
		web = "https://" + strings.TrimSpace(server.SSHHost)
	}
	web = strings.TrimRight(web, "/")
	if !strings.HasSuffix(web, "/") {
		web += "/"
	}
	parsed, err := url.Parse(web)
	if err != nil || parsed == nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errs.B().Code(errs.Unavailable).Msg("invalid eve-ng redirect target").Err()
	}
	return web, nil
}
