package skyforge

import (
	"net/http"
	"net/url"
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
	server, err := s.selectEveServer(targetName, projectID)
	if err != nil {
		return "", err
	}
	target := strings.TrimSpace(server.Name)
	if target == "" {
		target = "eve-default"
	}
	return "/api/skyforge/api/eve/sso?server=" + url.QueryEscape(target), nil
}

func (s *Service) selectEveServer(targetName, projectID string) (*EveServerConfig, error) {
	targetName = strings.TrimSpace(targetName)
	projectID = strings.TrimSpace(projectID)
	if targetName == "" && projectID != "" {
		if projects, err := s.projectStore.load(); err == nil {
			if p := findProjectByKey(projects, projectID); p != nil && strings.TrimSpace(p.EveServer) != "" {
				targetName = strings.TrimSpace(p.EveServer)
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
