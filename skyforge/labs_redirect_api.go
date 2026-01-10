package skyforge

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
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
		r.Header.Del("Accept-Encoding")
	}
	proxy.Transport = &http.Transport{
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: server.SkipTLSVerify},
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		location := resp.Header.Get("Location")
		if location == "" {
			return rewriteEveHTML(resp, "/labs/"+serverName)
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
		return rewriteEveHTML(resp, "/labs/"+serverName)
	}

	proxy.ServeHTTP(w, req)
}

func rewriteEveHTML(resp *http.Response, prefix string) error {
	body, err := readMaybeGzip(resp)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	rewritten := body
	if bytes.Contains(rewritten, []byte(`/assets/`)) || bytes.Contains(rewritten, []byte(`assets/`)) || bytes.Contains(rewritten, []byte("<html")) {
		prefixedAssets := []byte(prefix + "/assets/")
		plainPrefixedAssets := []byte(strings.TrimPrefix(prefix, "/") + "/assets/")
		token := []byte("__SF_EVE_ASSETS__")
		rewritten = bytes.ReplaceAll(rewritten, prefixedAssets, token)
		rewritten = bytes.ReplaceAll(rewritten, plainPrefixedAssets, token)
		rewritten = bytes.ReplaceAll(rewritten, []byte(`/assets/`), prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, []byte(`assets/`), prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, token, prefixedAssets)
		doublePrefix := []byte(prefix + "/" + strings.TrimPrefix(prefix, "/") + "/assets/")
		doubleSlashPrefix := []byte(prefix + "//" + strings.TrimPrefix(prefix, "/") + "/assets/")
		protoRelativePrefix := []byte("//" + strings.TrimPrefix(prefix, "/") + "/assets/")
		httpsPrefix := []byte("https://" + strings.TrimPrefix(prefix, "/") + "/assets/")
		httpPrefix := []byte("http://" + strings.TrimPrefix(prefix, "/") + "/assets/")
		protoRelativeBase := []byte("//" + strings.TrimPrefix(prefix, "/") + "/")
		rewritten = bytes.ReplaceAll(rewritten, doublePrefix, prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, doubleSlashPrefix, prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, protoRelativePrefix, prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, httpsPrefix, prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, httpPrefix, prefixedAssets)
		rewritten = bytes.ReplaceAll(rewritten, protoRelativeBase, []byte(prefix+"/"))
	}
	if bytes.Contains(rewritten, []byte("<head>")) {
		prefixLiteral := strconv.Quote(prefix + "/")
		badPrefix := strconv.Quote("https://" + strings.TrimPrefix(prefix, "/") + "/")
		badPrefixAlt := strconv.Quote("http://" + strings.TrimPrefix(prefix, "/") + "/")
		fixScript := []byte(`<script>(()=>{const prefix=` + prefixLiteral + `;const bad=` + badPrefix + `;const badAlt=` + badPrefixAlt + `;const badProto="//` + strings.TrimPrefix(prefix, "/") + `/";const rewrite=v=>{if(typeof v!=="string")return v;if(v.startsWith(bad))return prefix+v.slice(bad.length);if(v.startsWith(badAlt))return prefix+v.slice(badAlt.length);if(v.startsWith(badProto))return prefix+v.slice(badProto.length);return v;};const fix=l=>{if(!l||!l.href)return;l.href=rewrite(l.href);};const origSetAttr=Element.prototype.setAttribute;Element.prototype.setAttribute=function(name,value){if(this.tagName==="LINK"&&name==="href")value=rewrite(value);return origSetAttr.call(this,name,value);};const desc=Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype,"href");if(desc&&desc.set){Object.defineProperty(HTMLLinkElement.prototype,"href",{get:desc.get,set(v){desc.set.call(this,rewrite(v));}});}document.querySelectorAll('link[rel="modulepreload"]').forEach(fix);new MutationObserver(m=>{for(const r of m){for(const n of r.addedNodes){if(n.tagName==="LINK"&&n.rel==="modulepreload"){fix(n);}}}}).observe(document.documentElement,{childList:true,subtree:true});})();</script>`)
		rewritten = bytes.Replace(rewritten, []byte("<head>"), append([]byte("<head>"), fixScript...), 1)
	}
	if err := writeMaybeGzip(resp, rewritten); err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		resp.ContentLength = int64(len(rewritten))
		resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	}
	return nil
}

func readMaybeGzip(resp *http.Response) ([]byte, error) {
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		return io.ReadAll(resp.Body)
	}
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func writeMaybeGzip(resp *http.Response, data []byte) error {
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		resp.Body = io.NopCloser(bytes.NewReader(data))
		return nil
	}
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	resp.ContentLength = int64(buf.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
	return nil
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
