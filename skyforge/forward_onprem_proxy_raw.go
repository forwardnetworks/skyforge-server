package skyforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Forward on-prem autosleep/wake support.
//
// This is intentionally limited for demo environments where Forward runs in the same
// Kubernetes cluster as Skyforge and is exposed behind Skyforge SSO under /fwd.
//
// Envoy (forward-app-proxy) routes /fwd/* to this proxy endpoint when autosleep is
// enabled, and this handler will:
// - scale Forward workloads up on demand
// - proxy the HTTP request to fwd-appserver in the forward namespace
// - scale workloads down to 0 after an idle timeout

const (
	forwardOnPremProxyPrefix = "/api/forward/onprem/proxy"
)

const (
	forwardOnPremCookiePathModePrefix = "prefix"
	forwardOnPremCookiePathModeAlias  = "alias"
)

var forwardOnPremAutosleepState struct {
	mu sync.Mutex

	enabled     bool
	idleTimeout time.Duration
	wakeTimeout time.Duration

	lastRequestAt time.Time
	timer         *time.Timer

	initOnce sync.Once
}

func forwardOnPremAutosleepEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_AUTOSLEEP_ENABLED"))
	if raw == "" {
		return false
	}
	raw = strings.ToLower(raw)
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func forwardOnPremAutosleepIdleTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_AUTOSLEEP_IDLE_MINUTES"))
	mins, err := strconv.Atoi(raw)
	if err != nil || mins <= 0 {
		mins = 30
	}
	if mins < 1 {
		mins = 1
	}
	if mins > 24*60 {
		mins = 24 * 60
	}
	return time.Duration(mins) * time.Minute
}

func forwardOnPremAutosleepWakeTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_ONPREM_WAKE_TIMEOUT_SECONDS"))
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		secs = 180
	}
	if secs < 10 {
		secs = 10
	}
	if secs > 15*60 {
		secs = 15 * 60
	}
	return time.Duration(secs) * time.Second
}

func forwardOnPremInitAutosleepState() {
	forwardOnPremAutosleepState.mu.Lock()
	defer forwardOnPremAutosleepState.mu.Unlock()

	forwardOnPremAutosleepState.enabled = forwardOnPremAutosleepEnabled()
	forwardOnPremAutosleepState.idleTimeout = forwardOnPremAutosleepIdleTimeout()
	forwardOnPremAutosleepState.wakeTimeout = forwardOnPremAutosleepWakeTimeout()
}

func forwardOnPremNoteRequestLocked(now time.Time) {
	forwardOnPremAutosleepState.lastRequestAt = now
	if forwardOnPremAutosleepState.timer == nil {
		return
	}
	// Reset timer to fire at now + idleTimeout.
	forwardOnPremAutosleepState.timer.Reset(forwardOnPremAutosleepState.idleTimeout)
}

func forwardOnPremStartIdleTimerLocked() {
	if !forwardOnPremAutosleepState.enabled {
		return
	}
	if forwardOnPremAutosleepState.timer != nil {
		return
	}
	// Fire after idleTimeout since last request. If no requests yet, start the clock now.
	if forwardOnPremAutosleepState.lastRequestAt.IsZero() {
		forwardOnPremAutosleepState.lastRequestAt = time.Now()
	}
	forwardOnPremAutosleepState.timer = time.AfterFunc(forwardOnPremAutosleepState.idleTimeout, func() {
		forwardOnPremHandleIdle()
	})
}

func forwardOnPremHandleIdle() {
	now := time.Now()

	forwardOnPremAutosleepState.mu.Lock()
	if !forwardOnPremAutosleepState.enabled {
		forwardOnPremAutosleepState.mu.Unlock()
		return
	}
	last := forwardOnPremAutosleepState.lastRequestAt
	idleTimeout := forwardOnPremAutosleepState.idleTimeout
	// If there was recent activity, reschedule.
	if !last.IsZero() && now.Sub(last) < idleTimeout {
		if forwardOnPremAutosleepState.timer != nil {
			forwardOnPremAutosleepState.timer.Reset(idleTimeout - now.Sub(last))
		}
		forwardOnPremAutosleepState.mu.Unlock()
		return
	}
	// Reschedule immediately after scaling down so the timer remains active.
	if forwardOnPremAutosleepState.timer != nil {
		forwardOnPremAutosleepState.timer.Reset(idleTimeout)
	}
	forwardOnPremAutosleepState.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := forwardOnPremScale(ctx, 0); err != nil {
		rlog.Warn("forward onprem autosleep scale down failed", "err", err)
		return
	}
	rlog.Info("forward onprem autosleep scaled down to 0 (idle)", "idle_timeout", idleTimeout.String())
}

// forwardOnPremScale sets desired replicas for the "minimal app" Forward workloads.
func forwardOnPremScale(ctx context.Context, replicas int32) error {
	const ns = "forward"

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return err
	}

	// Minimal set for demos: app + workers + log aggregation + collector + CBR.
	// Autopilot is intentionally excluded.
	deployments := []string{
		"fwd-backend-master",
		"fwd-appserver",
		"fwd-collector",
		"fwd-cbr-agent",
		"fwd-cbr-s3-agent",
		"fwd-cbr-server",
	}
	statefulsets := []string{
		"fwd-compute-worker",
		"fwd-search-worker",
		"fwd-log-aggregator",
	}

	for _, name := range deployments {
		if err := scaleDeployment(ctx, clientset, ns, name, replicas); err != nil {
			return fmt.Errorf("scale deployment %s/%s: %w", ns, name, err)
		}
	}
	for _, name := range statefulsets {
		if err := scaleStatefulSet(ctx, clientset, ns, name, replicas); err != nil {
			return fmt.Errorf("scale statefulset %s/%s: %w", ns, name, err)
		}
	}
	return nil
}

func scaleDeployment(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string, replicas int32) error {
	for i := 0; i < 5; i++ {
		d, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		cur := int32(1)
		if d.Spec.Replicas != nil {
			cur = *d.Spec.Replicas
		}
		if cur == replicas {
			return nil
		}
		d = d.DeepCopy()
		d.Spec.Replicas = &replicas
		if _, err := clientset.AppsV1().Deployments(namespace).Update(ctx, d, metav1.UpdateOptions{}); err != nil {
			// Best-effort retry on conflict.
			if strings.Contains(strings.ToLower(err.Error()), "conflict") {
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("too many deployment update conflicts")
}

func scaleStatefulSet(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string, replicas int32) error {
	for i := 0; i < 5; i++ {
		sts, err := clientset.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		cur := int32(1)
		if sts.Spec.Replicas != nil {
			cur = *sts.Spec.Replicas
		}
		if cur == replicas {
			return nil
		}
		sts = sts.DeepCopy()
		sts.Spec.Replicas = &replicas
		if _, err := clientset.AppsV1().StatefulSets(namespace).Update(ctx, sts, metav1.UpdateOptions{}); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "conflict") {
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("too many statefulset update conflicts")
}

func forwardOnPremEnsureAwake(ctx context.Context, wakeTimeout time.Duration) error {
	if err := forwardOnPremScale(ctx, 1); err != nil {
		return err
	}
	ctxWait, cancel := context.WithTimeout(ctx, wakeTimeout)
	defer cancel()
	return forwardOnPremWaitReady(ctxWait)
}

func forwardOnPremWaitReady(ctx context.Context) error {
	const ns = "forward"

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return err
	}

	// Wait on core UI/backend + workers. CBR is helpful but don't block forever for it.
	type depReady struct {
		name          string
		needAvailable int32
		optional      bool
	}
	type stsReady struct {
		name      string
		needReady int32
		optional  bool
	}

	deps := []depReady{
		{name: "fwd-backend-master", needAvailable: 1},
		{name: "fwd-appserver", needAvailable: 1},
		{name: "fwd-collector", needAvailable: 1, optional: true},
		{name: "fwd-cbr-agent", needAvailable: 1, optional: true},
		{name: "fwd-cbr-s3-agent", needAvailable: 1, optional: true},
		{name: "fwd-cbr-server", needAvailable: 1, optional: true},
	}
	stss := []stsReady{
		{name: "fwd-compute-worker", needReady: 1},
		{name: "fwd-search-worker", needReady: 1},
		{name: "fwd-log-aggregator", needReady: 1, optional: true},
	}

	deadline, _ := ctx.Deadline()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		allOK := true

		for _, d := range deps {
			obj, err := clientset.AppsV1().Deployments(ns).Get(ctx, d.name, metav1.GetOptions{})
			if err != nil {
				if d.optional {
					continue
				}
				allOK = false
				break
			}
			if obj.Status.AvailableReplicas < d.needAvailable {
				if d.optional {
					continue
				}
				allOK = false
				break
			}
		}
		if allOK {
			for _, s := range stss {
				obj, err := clientset.AppsV1().StatefulSets(ns).Get(ctx, s.name, metav1.GetOptions{})
				if err != nil {
					if s.optional {
						continue
					}
					allOK = false
					break
				}
				if obj.Status.ReadyReplicas < s.needReady {
					if s.optional {
						continue
					}
					allOK = false
					break
				}
			}
		}

		if allOK {
			return nil
		}

		// Poll.
		sleep := 2 * time.Second
		if !deadline.IsZero() && time.Until(deadline) < 10*time.Second {
			sleep = 500 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

func forwardOnPremProxyTarget() (*url.URL, error) {
	// Intentionally hard-coded for now; keep this simple for on-prem demos.
	return url.Parse("https://fwd-appserver.forward.svc.cluster.local:8443")
}

func forwardOnPremProxyPath(reqPath string) string {
	p := strings.TrimSpace(reqPath)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasPrefix(p, forwardOnPremProxyPrefix) {
		p = strings.TrimPrefix(p, forwardOnPremProxyPrefix)
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// In root-alias mode, avoid hitting upstream "/" (which sets REDIRECT_URI and
	// can cause login redirect churn). Go straight to /login.
	if p == "/" && forwardOnPremRootAliasesEnabled() {
		return "/login"
	}
	return p
}

func (s *Service) forwardOnPremProxyRaw(w http.ResponseWriter, req *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		// Map auth failures to HTTP.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_ = user
	rlog.Info("forward onprem request",
		"path", req.URL.Path,
		"host", req.Host,
		"xfh", strings.TrimSpace(req.Header.Get("X-Forwarded-Host")),
		"xfp", strings.TrimSpace(req.Header.Get("X-Forwarded-Prefix")),
		"cookie_names", cookieHeaderNames(req.Header.Get("Cookie")),
	)

	forwardOnPremAutosleepState.initOnce.Do(forwardOnPremInitAutosleepState)

	now := time.Now()
	forwardOnPremAutosleepState.mu.Lock()
	forwardOnPremNoteRequestLocked(now)
	forwardOnPremStartIdleTimerLocked()
	enabled := forwardOnPremAutosleepState.enabled
	wakeTimeout := forwardOnPremAutosleepState.wakeTimeout
	forwardOnPremAutosleepState.mu.Unlock()

	if enabled {
		// Always kick off a scale-up (idempotent) but avoid holding the browser
		// request open for minutes. If Forward isn't ready quickly, return a
		// small "waking up" response and let the browser retry.
		ctxScale, cancel := context.WithTimeout(req.Context(), 30*time.Second)
		if err := forwardOnPremScale(ctxScale, 1); err != nil {
			cancel()
			rlog.Warn("forward onprem wake failed (scale)", "err", err)
			writeForwardOnPremWaking(w, req, err)
			return
		}
		cancel()

		blockWait := 5 * time.Second
		if wakeTimeout > 0 && wakeTimeout < blockWait {
			blockWait = wakeTimeout
		}
		if blockWait < 500*time.Millisecond {
			blockWait = 500 * time.Millisecond
		}

		ctxWait, cancel := context.WithTimeout(req.Context(), blockWait)
		err := forwardOnPremWaitReady(ctxWait)
		cancel()
		if err != nil {
			rlog.Info("forward onprem waking up", "err", err, "block_wait", blockWait.String())
			writeForwardOnPremWaking(w, req, err)
			return
		}
	}

	target, err := forwardOnPremProxyTarget()
	if err != nil {
		rlog.Error("forward onprem proxy target invalid", "err", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// Preserve the original request, but map /api/forward/onprem/proxy/* -> / on the upstream.
	upPath := forwardOnPremProxyPath(req.URL.Path)
	upQuery := ""
	if req.URL != nil {
		upQuery = req.URL.RawQuery
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Forward appserver uses internal/self-signed certs.
	}
	origDirector := proxy.Director
	origHost := strings.TrimSpace(req.Host)
	if origHost == "" {
		origHost = strings.TrimSpace(req.Header.Get("X-Forwarded-Host"))
	}
	publicScheme := ""
	if u, err := url.Parse(strings.TrimSpace(s.cfg.PublicURL)); err == nil {
		publicScheme = strings.TrimSpace(u.Scheme)
	}
	redirectHost := origHost
	if redirectHost == "" {
		redirectHost = strings.TrimSpace(req.Header.Get("X-Forwarded-Host"))
	}
	rootAliasesEnabled := forwardOnPremRootAliasesEnabled()
	cookiePathMode := forwardOnPremCookiePathMode(rootAliasesEnabled)
	proxy.Director = func(r *http.Request) {
		if origDirector != nil {
			origDirector(r)
		}
		r.URL.Path = upPath
		r.URL.RawPath = ""
		r.URL.RawQuery = upQuery

		// Important: do NOT set Host to the upstream service DNS name.
		// When Host is the internal cluster.local name, Forward issues redirects to
		// internal URLs (e.g. https://fwd-appserver.forward.svc.cluster.local:8443/)
		// which the browser cannot resolve.
		//
		// Keep the external host so Forward generates browser-valid redirects.
		extHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
		if extHost == "" {
			extHost = origHost
		}
		if extHost != "" {
			r.Host = extHost
			if strings.TrimSpace(r.Header.Get("X-Forwarded-Host")) == "" {
				r.Header.Set("X-Forwarded-Host", extHost)
			}
		}

		// Always propagate the external scheme to Forward. Intermediate proxies may
		// set X-Forwarded-Proto=http for in-cluster hops, which can trigger
		// self-redirect loops at /login.
		scheme := publicScheme
		if scheme == "" {
			// Skyforge is almost always served over HTTPS.
			scheme = "https"
		}
		r.Header.Set("X-Forwarded-Proto", scheme)
		if strings.EqualFold(scheme, "https") {
			r.Header.Set("X-Forwarded-Port", "443")
		}
		// Keep responses uncompressed so response-body rewrites are safe.
		r.Header.Del("Accept-Encoding")

		// If Envoy already provided a prefix header, keep it. It helps Forward build absolute URLs.
		if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Prefix")); v == "" {
			r.Header.Set("X-Forwarded-Prefix", "/fwd")
		}

		// Prevent same-host cookie collisions (Skyforge and Forward both use web sessions).
		// Keep only Forward-relevant cookies when proxying to fwd-appserver.
		sanitizeForwardOnPremCookies(r)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		rewriteForwardOnPremSetCookiePaths(resp, cookiePathMode)
		if err := rewriteForwardOnPremJSONLocation(resp, redirectHost, publicScheme, rootAliasesEnabled); err != nil {
			return err
		}
		if err := rewriteForwardOnPremAssetAbsolutePaths(resp); err != nil {
			return err
		}

		loc := strings.TrimSpace(resp.Header.Get("Location"))
		if loc == "" {
			return nil
		}
		origLoc := loc
		if rewritten := rewriteForwardOnPremRedirectLocation(loc, redirectHost, publicScheme, rootAliasesEnabled); strings.TrimSpace(rewritten) != "" && rewritten != loc {
			resp.Header.Set("Location", rewritten)
			loc = rewritten
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			upPath := ""
			if resp.Request != nil && resp.Request.URL != nil {
				upPath = resp.Request.URL.Path
			}
			rlog.Info("forward onprem redirect",
				"status", resp.StatusCode,
				"upstream_path", upPath,
				"location", loc,
				"location_orig", origLoc,
				"root_aliases", rootAliasesEnabled,
				"cookie_mode", cookiePathMode,
			)
		}
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, e error) {
		rlog.Warn("forward onprem proxy upstream error", "err", e)
		rw.WriteHeader(http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, req)
}

func rewriteForwardOnPremJSONLocation(resp *http.Response, externalHost, externalScheme string, rootAliasesEnabled bool) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	ctype := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if !strings.Contains(ctype, "application/json") {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	rewritten, changed := rewriteForwardOnPremJSONLocationBody(body, externalHost, externalScheme, rootAliasesEnabled)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	return nil
}

func rewriteForwardOnPremJSONLocationBody(body []byte, externalHost, externalScheme string, rootAliasesEnabled bool) ([]byte, bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, false
	}
	rawLoc, _ := payload["location"].(string)
	rawLoc = strings.TrimSpace(rawLoc)
	if rawLoc == "" {
		return body, false
	}
	rewritten := rewriteForwardOnPremRedirectLocation(rawLoc, externalHost, externalScheme, rootAliasesEnabled)
	rewritten = strings.TrimSpace(rewritten)
	if rewritten == "" || rewritten == rawLoc {
		return body, false
	}
	payload["location"] = rewritten
	out, err := json.Marshal(payload)
	if err != nil {
		return body, false
	}
	return out, true
}

func rewriteForwardOnPremAssetAbsolutePaths(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	ctype := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	reqPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		reqPath = strings.TrimSpace(resp.Request.URL.Path)
	}
	isJSAsset := strings.Contains(reqPath, "/app/assets/") && strings.HasSuffix(strings.ToLower(reqPath), ".js")
	if !(strings.Contains(ctype, "text/html") || strings.Contains(ctype, "javascript") || isJSAsset) {
		return nil
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	rewritten, changed := rewriteForwardOnPremBodyPublicPaths(body)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	return nil
}

func rewriteForwardOnPremBodyPublicPaths(body []byte) ([]byte, bool) {
	in := string(body)
	replacer := strings.NewReplacer(
		`"/api/`, `"/fwd/api/`,
		`'/api/`, `'/fwd/api/`,
		`"/release-notes"`, `"/fwd/release-notes"`,
		`'/release-notes'`, `'/fwd/release-notes'`,
		`"/release-notes/`, `"/fwd/release-notes/`,
		`'/release-notes/`, `'/fwd/release-notes/`,
		`"/docs`, `"/fwd/docs`,
		`'/docs`, `'/fwd/docs`,
		`"/api-doc`, `"/fwd/api-doc`,
		`'/api-doc`, `'/fwd/api-doc`,
		`"/swagger`, `"/fwd/swagger`,
		`'/swagger`, `'/fwd/swagger`,
		`"/v3/api-docs`, `"/fwd/v3/api-docs`,
		`'/v3/api-docs`, `'/fwd/v3/api-docs`,
		`"/html/assets`, `"/fwd/html/assets`,
		`'/html/assets`, `'/fwd/html/assets`,
		`"/img/`, `"/fwd/img/`,
		`'/img/`, `'/fwd/img/`,
		`"/favicon.ico`, `"/fwd/favicon.ico`,
		`'/favicon.ico`, `'/fwd/favicon.ico`,
	)
	out := replacer.Replace(in)
	if out == in {
		return body, false
	}
	return []byte(out), true
}

func writeForwardOnPremWaking(w http.ResponseWriter, req *http.Request, err error) {
	// Encourage clients and intermediate caches not to store the transient wake response.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")

	accept := strings.ToLower(req.Header.Get("Accept"))
	if strings.Contains(accept, "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		// Keep HTML tiny and dependency-free; this is served before Forward is ready.
		_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="refresh" content="5" />
  <title>Forward is waking up</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 32px; background: #0b1220; color: #e6edf7; }
    .card { max-width: 720px; margin: 0 auto; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.14); border-radius: 14px; padding: 20px 18px; }
    h1 { font-size: 18px; margin: 0 0 8px; }
    p { margin: 0 0 10px; line-height: 1.4; color: rgba(230,237,247,0.85); }
    a { color: #9dd7ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    code { background: rgba(0,0,0,0.35); padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Forward is waking up</h1>
    <p>Skyforge is starting the on-prem Forward workloads. This page will retry automatically in 5 seconds.</p>
    <p>If it doesn’t load, click <a href="">Retry now</a>.</p>
    <p style="opacity:0.7;font-size:12px;margin-top:12px;">(If this keeps repeating, check Forward pod readiness in the <code>forward</code> namespace.)</p>
  </div>
</body>
</html>`))
		return
	}

	// Non-browser clients (Forward XHR, CLI, etc).
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("Forward is waking up; please retry.\n"))
	_ = err
}

func rewriteForwardOnPremRedirectLocation(location, externalHost, externalScheme string, rootAliasesEnabled bool) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	externalScheme = strings.TrimSpace(externalScheme)
	if externalScheme == "" {
		externalScheme = "https"
	}

	// Most Forward redirects are absolute-path locations (for example "/login").
	if strings.HasPrefix(location, "/") {
		if location == "/" {
			// Always send browser back to the mounted prefix root after successful
			// Forward login. Root-alias redirects ("/login") can be claimed by
			// Skyforge catch-all routing and bounce users out of /fwd.
			return "/fwd/"
		}
		if rootAliasesEnabled && (location == "/login" || location == "/logout") {
			return location
		}
		if strings.HasPrefix(location, "/fwd/") || location == "/fwd" {
			return location
		}
		return "/fwd" + location
	}

	u, err := url.Parse(location)
	if err != nil || !u.IsAbs() {
		return location
	}

	hostOnly := normalizeHostForCompare(u.Host)
	extHostOnly := normalizeHostForCompare(externalHost)
	if !isForwardInternalHost(hostOnly) && (extHostOnly == "" || hostOnly != extHostOnly) {
		return location
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if path == "/" {
		u.Path = "/fwd/"
		u.RawPath = ""
	} else if rootAliasesEnabled && (path == "/login" || path == "/logout") {
		// Keep canonical root aliases when enabled.
	} else if !strings.HasPrefix(path, "/fwd/") && path != "/fwd" {
		u.Path = "/fwd" + u.Path
		if strings.TrimSpace(u.RawPath) != "" {
			u.RawPath = "/fwd" + u.RawPath
		}
	}

	// Never leak internal service DNS names in browser redirects.
	if isForwardInternalHost(hostOnly) && strings.TrimSpace(externalHost) != "" {
		u.Host = strings.TrimSpace(externalHost)
	}
	if strings.TrimSpace(u.Scheme) == "" || isForwardInternalHost(hostOnly) || (extHostOnly != "" && hostOnly == extHostOnly) {
		u.Scheme = externalScheme
	}
	return u.String()
}

func rewriteForwardOnPremSetCookiePaths(resp *http.Response, mode string) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		mode = forwardOnPremCookiePathModePrefix
	}
	if mode != forwardOnPremCookiePathModePrefix {
		return
	}

	values := resp.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}

	rewritten := make([]string, 0, len(values))
	for _, v := range values {
		parts := strings.Split(v, ";")
		if len(parts) == 0 {
			continue
		}
		foundPath := false
		for i := 1; i < len(parts); i++ {
			attr := strings.TrimSpace(parts[i])
			if attr == "" {
				continue
			}
			lower := strings.ToLower(attr)
			if strings.HasPrefix(lower, "path=") {
				foundPath = true
				p := strings.TrimSpace(attr[len("path="):])
				if p == "/" {
					parts[i] = " Path=/fwd"
				}
			}
		}
		if !foundPath {
			parts = append(parts, " Path=/fwd")
		}
		rewritten = append(rewritten, strings.Join(parts, ";"))
	}
	if len(rewritten) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	for _, v := range rewritten {
		resp.Header.Add("Set-Cookie", v)
	}
}

func sanitizeForwardOnPremCookies(r *http.Request) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}
	kept := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		// Strip only Skyforge auth cookie(s); keep all Forward cookies so the
		// upstream app can complete its own login/session flow.
		if strings.EqualFold(strings.TrimSpace(c.Name), "skyforge_session") {
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

func cookieHeaderNames(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "=")
		name := p
		if idx >= 0 {
			name = strings.TrimSpace(p[:idx])
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func forwardOnPremRootAliasesEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("SKYFORGE_FORWARD_ONPREM_ROOT_ALIASES_ENABLED")))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func forwardOnPremCookiePathMode(rootAliasesEnabled bool) string {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("SKYFORGE_FORWARD_ONPREM_COOKIE_PATH_MODE")))
	switch raw {
	case forwardOnPremCookiePathModeAlias, forwardOnPremCookiePathModePrefix:
		return raw
	}
	if rootAliasesEnabled {
		return forwardOnPremCookiePathModeAlias
	}
	return forwardOnPremCookiePathModePrefix
}

func normalizeHostForCompare(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	// Best-effort strip of :port when present.
	if h, p, err := net.SplitHostPort(host); err == nil {
		if strings.TrimSpace(h) != "" && strings.TrimSpace(p) != "" {
			return h
		}
	}
	return host
}

func isForwardInternalHost(host string) bool {
	host = normalizeHostForCompare(host)
	return host == "fwd-appserver.forward.svc.cluster.local" || strings.HasSuffix(host, ".forward.svc.cluster.local")
}

// ForwardOnPremProxyGET proxies a Forward on-prem UI/API request under Skyforge SSO.
//
// Envoy (forward-app-proxy) rewrites /fwd/* to /api/forward/onprem/proxy/* so the
// server can wake the Forward workloads before proxying.
//
//encore:api auth raw method=GET path=/api/forward/onprem/proxy/*rest
func (s *Service) ForwardOnPremProxyGET(w http.ResponseWriter, req *http.Request) {
	s.forwardOnPremProxyRaw(w, req)
}

//encore:api auth raw method=POST path=/api/forward/onprem/proxy/*rest
func (s *Service) ForwardOnPremProxyPOST(w http.ResponseWriter, req *http.Request) {
	s.forwardOnPremProxyRaw(w, req)
}

//encore:api auth raw method=PUT path=/api/forward/onprem/proxy/*rest
func (s *Service) ForwardOnPremProxyPUT(w http.ResponseWriter, req *http.Request) {
	s.forwardOnPremProxyRaw(w, req)
}

//encore:api auth raw method=DELETE path=/api/forward/onprem/proxy/*rest
func (s *Service) ForwardOnPremProxyDELETE(w http.ResponseWriter, req *http.Request) {
	s.forwardOnPremProxyRaw(w, req)
}

//encore:api auth raw method=PATCH path=/api/forward/onprem/proxy/*rest
func (s *Service) ForwardOnPremProxyPATCH(w http.ResponseWriter, req *http.Request) {
	s.forwardOnPremProxyRaw(w, req)
}

// AdminForwardOnPremScaleDown is an internal helper endpoint for debugging.
//
//encore:api auth method=POST path=/api/admin/forward/onprem/scale-down tag:admin
func (s *Service) AdminForwardOnPremScaleDown(ctx context.Context) error {
	// Keep this behind admin auth. Useful when debugging without waiting for idle timeout.
	if err := forwardOnPremScale(ctx, 0); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to scale down forward onprem").Err()
	}
	return nil
}
