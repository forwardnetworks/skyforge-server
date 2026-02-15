package skyforge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	encoreErrors "encore.dev/beta/errs"
)

func webuiProxyClusterHost(serviceName, namespace string, port int) string {
	serviceName = strings.TrimSpace(serviceName)
	namespace = strings.TrimSpace(namespace)
	if serviceName == "" || namespace == "" || port <= 0 {
		return ""
	}
	// Use the cluster-local DNS name so the server can reach it without relying on
	// client-side DNS or any node-specific networking.
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", serviceName, namespace, port)
}

func webuiProxyBasePath(reqPath string) string {
	// /api/workspaces/:id/deployments/:deploymentID/nodes/:node/webui/*rest
	if reqPath == "" {
		return ""
	}
	if i := strings.Index(reqPath, "/webui/"); i >= 0 {
		return reqPath[:i+len("/webui/")]
	}
	if strings.HasSuffix(reqPath, "/webui") {
		return reqPath + "/"
	}
	return reqPath
}

func stripFrameHeaders(h http.Header) {
	if h == nil {
		return
	}
	h.Del("X-Frame-Options")

	// Best-effort strip CSP frame-ancestors directive. If parsing fails, keep CSP intact.
	csp := strings.TrimSpace(h.Get("Content-Security-Policy"))
	if csp == "" {
		return
	}
	parts := strings.Split(csp, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(p), "frame-ancestors ") || strings.EqualFold(p, "frame-ancestors") {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		h.Del("Content-Security-Policy")
		return
	}
	h.Set("Content-Security-Policy", strings.Join(out, "; "))
}

func (s *Service) deploymentNodeWebUIProxy(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceKey := strings.TrimSpace(req.PathValue("id"))
	deploymentID := strings.TrimSpace(req.PathValue("deploymentID"))
	node := strings.TrimSpace(req.PathValue("node"))
	rest := req.PathValue("rest")

	// Best-effort path param extraction for muxes that don't populate PathValue.
	if workspaceKey == "" || deploymentID == "" || node == "" {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		// expected: api/workspaces/<id>/deployments/<deploymentID>/nodes/<node>/webui/<rest?>
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "workspaces":
				if workspaceKey == "" {
					workspaceKey = strings.TrimSpace(parts[i+1])
				}
			case "deployments":
				if deploymentID == "" {
					deploymentID = strings.TrimSpace(parts[i+1])
				}
			case "nodes":
				if node == "" {
					node = strings.TrimSpace(parts[i+1])
				}
			}
		}
	}
	if workspaceKey == "" || deploymentID == "" || node == "" {
		http.Error(w, "invalid path params", http.StatusBadRequest)
		return
	}
	if wk, err := s.resolveWorkspaceKeyForClaims(claims, workspaceKey); err == nil && strings.TrimSpace(wk) != "" {
		workspaceKey = strings.TrimSpace(wk)
	}

	_, _, ws, err := s.loadWorkspaceByKey(workspaceKey)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if workspaceAccessLevelForClaims(s.cfg, ws, claims) == "none" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx := req.Context()
	dep, err := s.getWorkspaceDeployment(ctx, ws.ID, deploymentID)
	if err != nil || dep == nil {
		http.Error(w, "deployment not found", http.StatusNotFound)
		return
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		http.Error(w, "web ui proxy is only available for clabernetes-backed deployments", http.StatusBadRequest)
		return
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	k8sNamespace, _ := cfgAny["k8sNamespace"].(string)
	topologyName, _ := cfgAny["topologyName"].(string)
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	topologyName = strings.TrimSpace(topologyName)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesWorkspaceNamespace(ws.Slug)
	}
	if topologyName == "" {
		labName, _ := cfgAny["labName"].(string)
		topologyName = clabernetesTopologyName(strings.TrimSpace(labName))
	}
	if topologyName == "" {
		http.Error(w, "missing topology name", http.StatusPreconditionFailed)
		return
	}

	port := 443
	if raw := strings.TrimSpace(req.URL.Query().Get("port")); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	serviceName := fmt.Sprintf("%s-%s", topologyName, node)
	upstreamHost := webuiProxyClusterHost(serviceName, k8sNamespace, port)
	if upstreamHost == "" {
		http.Error(w, "missing upstream host", http.StatusPreconditionFailed)
		return
	}

	upstreamBase, err := url.Parse(fmt.Sprintf("%s://%s", scheme, upstreamHost))
	if err != nil {
		http.Error(w, "invalid upstream", http.StatusInternalServerError)
		return
	}

	embed := strings.EqualFold(strings.TrimSpace(req.URL.Query().Get("embed")), "1") ||
		strings.EqualFold(strings.TrimSpace(req.URL.Query().Get("embed")), "true")

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // internal lab devices often use self-signed certs
		},
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamBase)
	proxy.Transport = transport

	basePath := webuiProxyBasePath(req.URL.Path)
	if rest == "" {
		// Fallback: trim everything up to /webui/.
		if i := strings.Index(req.URL.Path, "/webui/"); i >= 0 {
			rest = strings.TrimPrefix(req.URL.Path[i+len("/webui/"):], "/")
		}
	}

	// Remove proxy-only query params before forwarding.
	q := req.URL.Query()
	q.Del("port")
	q.Del("embed")

	proxy.Director = func(r *http.Request) {
		r.URL.Scheme = upstreamBase.Scheme
		r.URL.Host = upstreamBase.Host
		r.Host = upstreamBase.Host
		r.URL.Path = "/" + strings.TrimPrefix(rest, "/")
		r.URL.RawQuery = q.Encode()
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if embed {
			stripFrameHeaders(resp.Header)
		}

		// Rewrite redirects back through this proxy to keep the browser on the same origin.
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		if loc == "" {
			return nil
		}

		// Handle relative redirects.
		locURL, err := url.Parse(loc)
		if err != nil {
			return nil
		}
		if locURL.IsAbs() {
			// Only rewrite redirects pointing back to the upstream host (or the internal mgmt IP).
			if !strings.EqualFold(locURL.Host, upstreamBase.Host) && !strings.EqualFold(locURL.Hostname(), "169.254.100.2") {
				return nil
			}
		}

		next := *req.URL
		next.Path = basePath + strings.TrimPrefix(locURL.Path, "/")

		nextQ := next.Query()
		nextQ.Set("port", fmt.Sprintf("%d", port))
		if embed {
			nextQ.Set("embed", "1")
		}
		for k, vals := range locURL.Query() {
			nextQ.Del(k)
			for _, v := range vals {
				nextQ.Add(k, v)
			}
		}
		next.RawQuery = nextQ.Encode()
		resp.Header.Set("Location", next.String())
		return nil
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			http.Error(rw, "request canceled", http.StatusGatewayTimeout)
			return
		}
		var e *url.Error
		if errors.As(err, &e) && e != nil && e.Timeout() {
			http.Error(rw, "upstream timeout", http.StatusGatewayTimeout)
			return
		}
		http.Error(rw, encoreErrors.B().Code(encoreErrors.Unavailable).Msg("upstream error").Err().Error(), http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, req)
}

// DeploymentNodeWebUIProxy (GET)
//
//encore:api auth raw method=GET path=/api/workspaces/:id/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxy(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

//encore:api auth raw method=POST path=/api/workspaces/:id/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyPost(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

//encore:api auth raw method=PUT path=/api/workspaces/:id/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyPut(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

//encore:api auth raw method=DELETE path=/api/workspaces/:id/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyDelete(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}

//encore:api auth raw method=PATCH path=/api/workspaces/:id/deployments/:deploymentID/nodes/:node/webui/*rest
func (s *Service) DeploymentNodeWebUIProxyPatch(w http.ResponseWriter, req *http.Request) {
	s.deploymentNodeWebUIProxy(w, req)
}
