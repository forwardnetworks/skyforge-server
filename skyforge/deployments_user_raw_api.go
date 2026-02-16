package skyforge

import "net/http"

// TerminalExecWSUser provides terminal websocket access without context path parameters.
//
//encore:api auth raw method=GET path=/api/deployments/:deploymentID/terminal/ws
func (s *Service) TerminalExecWSUser(w http.ResponseWriter, req *http.Request) {
	s.TerminalExecWS(w, req)
}

// DeploymentUIEventsStreamUser streams deployment UI events without context path parameters.
//
//encore:api auth raw method=GET path=/api/deployments/:deploymentID/ui-events/events
func (s *Service) DeploymentUIEventsStreamUser(w http.ResponseWriter, req *http.Request) {
	s.DeploymentUIEventsStream(w, req)
}

// DeploymentLinkStatsEventsUser streams link stats snapshots without context path parameters.
//
//encore:api auth raw method=GET path=/api/deployments/:deploymentID/links/stats/events
func (s *Service) DeploymentLinkStatsEventsUser(w http.ResponseWriter, req *http.Request) {
	s.GetUserDeploymentLinkStatsEvents(w, req)
}

// DeploymentNodeWebUIProxyUserGet proxies WebUI GET requests without context path parameters.
//
//encore:api auth raw method=GET path=/api/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyUserGet(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

// DeploymentNodeWebUIProxyUserPost proxies WebUI POST requests without context path parameters.
//
//encore:api auth raw method=POST path=/api/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyUserPost(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

// DeploymentNodeWebUIProxyUserPut proxies WebUI PUT requests without context path parameters.
//
//encore:api auth raw method=PUT path=/api/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyUserPut(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

// DeploymentNodeWebUIProxyUserDelete proxies WebUI DELETE requests without context path parameters.
//
//encore:api auth raw method=DELETE path=/api/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyUserDelete(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

// DeploymentNodeWebUIProxyUserPatch proxies WebUI PATCH requests without context path parameters.
//
//encore:api auth raw method=PATCH path=/api/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyUserPatch(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}
