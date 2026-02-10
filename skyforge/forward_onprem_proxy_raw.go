package skyforge

import (
	"context"
	"errors"
	"fmt"
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
// This is intentionally scoped for demo environments where Forward runs in the same
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
	return url.Parse("http://fwd-appserver.forward.svc.cluster.local:8080")
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

	forwardOnPremAutosleepState.initOnce.Do(forwardOnPremInitAutosleepState)

	now := time.Now()
	forwardOnPremAutosleepState.mu.Lock()
	forwardOnPremNoteRequestLocked(now)
	forwardOnPremStartIdleTimerLocked()
	enabled := forwardOnPremAutosleepState.enabled
	wakeTimeout := forwardOnPremAutosleepState.wakeTimeout
	forwardOnPremAutosleepState.mu.Unlock()

	if enabled {
		ctxWake, cancel := context.WithTimeout(req.Context(), wakeTimeout)
		defer cancel()
		if err := forwardOnPremEnsureAwake(ctxWake, wakeTimeout); err != nil {
			rlog.Warn("forward onprem wake failed", "err", err)
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Forward is waking up; please retry.\n"))
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
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		if origDirector != nil {
			origDirector(r)
		}
		r.URL.Path = upPath
		r.URL.RawPath = ""
		r.URL.RawQuery = upQuery
		// Forward expects host-based routing sometimes; set Host to upstream.
		r.Host = target.Host

		// If Envoy already provided a prefix header, keep it. It helps Forward build absolute URLs.
		if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Prefix")); v == "" {
			r.Header.Set("X-Forwarded-Prefix", "/fwd")
		}
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, e error) {
		rlog.Warn("forward onprem proxy upstream error", "err", e)
		rw.WriteHeader(http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, req)
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
