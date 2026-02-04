package skyforge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encore.dev/rlog"
	"encore.app/internal/terminalutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

func terminalWSAcceptOptions(publicURL string, req *http.Request) *websocket.AcceptOptions {
	if req == nil {
		return nil
	}

	normalizeHost := func(h string) string {
		h = strings.TrimSpace(h)
		h = strings.TrimPrefix(h, "http://")
		h = strings.TrimPrefix(h, "https://")
		if i := strings.IndexByte(h, '/'); i >= 0 {
			h = h[:i]
		}
		if host, _, err := net.SplitHostPort(h); err == nil {
			return strings.TrimSpace(host)
		}
		// Best-effort strip :port for common host:port cases.
		if strings.Count(h, ":") == 1 {
			return strings.TrimSpace(strings.SplitN(h, ":", 2)[0])
		}
		return strings.TrimSpace(h)
	}

	// Base domain allowlist:
	// - Prefer PublicURL (if set) as the canonical external hostname.
	// - Fall back to request Host.
	// Keep this reasonably tight to reduce WS CSRF exposure, but wide enough to
	// handle reverse proxies that don't preserve the Host header.
	baseDomainForHost := func(h string) string {
		h = strings.ToLower(normalizeHost(h))
		switch {
		case strings.HasSuffix(h, ".local.forwardnetworks.com") || h == "local.forwardnetworks.com":
			return "local.forwardnetworks.com"
		case strings.HasSuffix(h, ".forwardnetworks.com") || h == "forwardnetworks.com":
			return "forwardnetworks.com"
		default:
			return ""
		}
	}

	baseDomain := ""
	if publicURL != "" {
		if u, err := url.Parse(publicURL); err == nil {
			baseDomain = baseDomainForHost(u.Host)
		}
	}
	if baseDomain == "" {
		baseDomain = baseDomainForHost(req.Host)
	}

	allowed := map[string]struct{}{}
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" {
			return
		}
		// If we have a base domain, restrict hosts to that domain (or localhost for dev).
		if baseDomain != "" {
			lh := strings.ToLower(h)
			if lh != "localhost" && lh != "127.0.0.1" && lh != baseDomain && !strings.HasSuffix(lh, "."+baseDomain) {
				return
			}
		}
		allowed[strings.ToLower(h)] = struct{}{}
	}

	// Always include the request Host as a fallback.
	add(req.Host)

	// If we're behind a reverse proxy that doesn't preserve Host to the backend (passHostHeader=false),
	// nhooyr/websocket's default origin check can reject legitimate same-site browser connections.
	//
	// Browsers cannot set X-Forwarded-Host for WebSocket requests; it's set by the proxy, so it is safe
	// to use it to authorize the external origin host.
	for _, part := range strings.Split(req.Header.Get("X-Forwarded-Host"), ",") {
		add(part)
	}

	if publicURL != "" {
		if u, err := url.Parse(publicURL); err == nil {
			add(u.Host)
		}
	}

	// Origin is sent by the browser for WebSocket requests. If it falls under the
	// expected base domain, include it as well.
	if origin := strings.TrimSpace(req.Header.Get("Origin")); origin != "" {
		if u, err := url.Parse(origin); err == nil {
			add(u.Host)
		}
	}

	// Add wildcard patterns for the base domain to handle node-specific hostnames.
	if baseDomain != "" {
		allowed[strings.ToLower(baseDomain)] = struct{}{}
		allowed["*."+strings.ToLower(baseDomain)] = struct{}{}
	}

	if len(allowed) == 0 {
		return nil
	}

	patterns := make([]string, 0, len(allowed))
	for h := range allowed {
		patterns = append(patterns, h)
	}
	sort.Strings(patterns)
	return &websocket.AcceptOptions{OriginPatterns: patterns}
}

type terminalClientMsg struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

type terminalServerMsg struct {
	Type   string `json:"type"`
	Data   string `json:"data,omitempty"`
	Stream string `json:"stream,omitempty"`
}

type terminalSizeQueue struct {
	ch chan remotecommand.TerminalSize
}

func newTerminalSizeQueue() *terminalSizeQueue {
	return &terminalSizeQueue{ch: make(chan remotecommand.TerminalSize, 8)}
}

func (q *terminalSizeQueue) Next() *remotecommand.TerminalSize {
	size, ok := <-q.ch
	if !ok {
		return nil
	}
	return &size
}

func kubeInClusterConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// Be explicit about TLS defaults; allow insecure only if explicitly requested elsewhere.
	if cfg.TLSClientConfig.CAFile == "" {
		// Some distros mount CA at a standard location; fall back if present.
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
			cfg.TLSClientConfig.CAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
		}
	}
	if cfg.TLSClientConfig.Insecure {
		cfg.TLSClientConfig.Insecure = false
	}
	// Remotecommand uses the REST transport; keep timeouts conservative.
	cfg.Timeout = 30 * time.Second
	return cfg, nil
}

func resolveClabernetesNodePod(ctx context.Context, ns, topologyName, node string) (podName string, err error) {
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	node = strings.TrimSpace(node)
	if ns == "" || topologyName == "" || node == "" {
		return "", fmt.Errorf("namespace, topology name, and node are required")
	}

	// Reuse the existing in-cluster HTTP kube client used elsewhere in Skyforge (RBAC is already wired).
	client, err := kubeHTTPClient()
	if err != nil {
		return "", err
	}
	reqURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods?labelSelector=%s",
		url.PathEscape(ns),
		url.QueryEscape("clabernetes/topologyOwner="+topologyName+",clabernetes/topologyNode="+node),
	)
	req, err := kubeRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return "", fmt.Errorf("kube list pods failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if len(payload.Items) == 0 {
		return "", fmt.Errorf("node pod not found")
	}
	return strings.TrimSpace(payload.Items[0].Metadata.Name), nil
}

// TerminalExecWS provides an interactive in-browser terminal into clabernetes-backed nodes
// using Kubernetes `pods/exec` (SPDY) and a WebSocket transport to the browser.
//
// Query params:
// - node: required (clabernetes/topologyNode)
// - container: optional
// - command: optional (defaults to "sh"; for EOS nodes use "Cli")
//
//encore:api auth raw method=GET path=/api/workspaces/:id/deployments/:deploymentID/terminal/ws
func (s *Service) TerminalExecWS(w http.ResponseWriter, req *http.Request) {
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
	if workspaceKey == "" || deploymentID == "" {
		// Best-effort path param extraction (PathValue is only populated when the
		// underlying mux supports it).
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		// expected: api/workspaces/<id>/deployments/<deploymentID>/terminal/ws
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
			}
		}
	}
	if workspaceKey == "" || deploymentID == "" {
		http.Error(w, "invalid path params", http.StatusBadRequest)
		return
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

	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	dep, err := s.getWorkspaceDeployment(ctx, ws.ID, deploymentID)
	if err != nil || dep == nil {
		http.Error(w, "deployment not found", http.StatusNotFound)
		return
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	if typ != "netlab-c9s" && typ != "clabernetes" {
		http.Error(w, "terminal is only available for clabernetes-backed deployments", http.StatusBadRequest)
		return
	}

	node := strings.TrimSpace(req.URL.Query().Get("node"))
	if node == "" {
		http.Error(w, "node query param is required", http.StatusBadRequest)
		return
	}
	container := strings.TrimSpace(req.URL.Query().Get("container"))
	rawCommand := strings.TrimSpace(req.URL.Query().Get("command"))
	command := terminalutil.NormalizeCommand(rawCommand)
	cmd := strings.Fields(command)
	if len(cmd) == 0 {
		cmd = []string{"sh"}
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
		// When config is absent, fall back to labName-derived topology name.
		labName, _ := cfgAny["labName"].(string)
		topologyName = clabernetesTopologyName(strings.TrimSpace(labName))
	}
	if topologyName == "" {
		http.Error(w, "missing topology name", http.StatusPreconditionFailed)
		return
	}

	// Upgrade to websocket.
	conn, err := websocket.Accept(w, req, terminalWSAcceptOptions(s.cfg.PublicURL, req))
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 20)

	var lastClientActivityUnixNano atomic.Int64
	lastClientActivityUnixNano.Store(time.Now().UnixNano())

	// Keep the WebSocket alive through reverse proxies and idle periods.
	// Without this, some proxies close idle connections without a close frame,
	// which surfaces to the browser as code 1006.
	{
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					ctxPing, cancel := context.WithTimeout(ctx, 2*time.Second)
					err := conn.Ping(ctxPing)
					cancel()
					if err != nil {
						// If we can't ping the client, force-close to avoid leaving an orphaned
						// kube exec (and a vrnetlab console session) running indefinitely.
						cancel()
						_ = conn.Close(websocket.StatusGoingAway, "client ping failed")
						return
					}
				}
			}
		}()
	}

	// Safety net: if the browser disappears without a proper close, expire the session.
	// This is especially important for vrnetlab consoles which are effectively single-user.
	{
		idleTimeout := 5 * time.Minute
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					last := time.Unix(0, lastClientActivityUnixNano.Load())
					if time.Since(last) > idleTimeout {
						cancel()
						_ = conn.Close(websocket.StatusNormalClosure, "idle timeout")
						return
					}
				}
			}
		}()
	}

	// Resolve pod name.
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	podName, err := resolveClabernetesNodePod(resolveCtx, k8sNamespace, topologyName, node)
	cancel()
	if err != nil {
		_ = wsjson.Write(ctx, conn, terminalServerMsg{Type: "error", Data: err.Error()})
		return
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		_ = wsjson.Write(ctx, conn, terminalServerMsg{Type: "error", Data: "kube config unavailable"})
		return
	}

	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		_ = wsjson.Write(ctx, conn, terminalServerMsg{Type: "error", Data: "kube client unavailable"})
		return
	}

	// If container isn't specified and the pod has multiple containers, pick a sensible default.
	var pod *corev1.Pod
	if container == "" {
		ctxGet, cancel := context.WithTimeout(ctx, 3*time.Second)
		pod, err = clientset.CoreV1().Pods(k8sNamespace).Get(ctxGet, podName, metav1.GetOptions{})
		cancel()
		if err == nil && pod != nil {
			best := ""
			// Prefer the NOS container, which in clabernetes native mode is the topology node name.
			for _, c := range pod.Spec.Containers {
				name := strings.TrimSpace(c.Name)
				if name == "" {
					continue
				}
				if name == node {
					best = name
					break
				}
			}
			if best == "" {
				// Fall back to common container names, and avoid selecting the launcher when possible.
				bestNonLauncher := ""
				bestAny := ""
				for _, c := range pod.Spec.Containers {
					name := strings.TrimSpace(c.Name)
					if name == "" {
						continue
					}
					if bestAny == "" {
						bestAny = name
					}
					if name != "clabernetes-launcher" && bestNonLauncher == "" {
						bestNonLauncher = name
					}
					if name == "nos" {
						bestNonLauncher = name
						break
					}
					if name == "node" {
						bestNonLauncher = name
					}
				}
				if bestNonLauncher != "" {
					best = bestNonLauncher
				} else {
					best = bestAny
				}
			}
			container = best
		}
	} else {
		// We still fetch the pod to detect vrnetlab-backed nodes and pick a better
		// default terminal command.
		ctxGet, cancel := context.WithTimeout(ctx, 3*time.Second)
		pod, _ = clientset.CoreV1().Pods(k8sNamespace).Get(ctxGet, podName, metav1.GetOptions{})
		cancel()
	}

	// If the user didn't explicitly request a shell/command, prefer the vrnetlab
	// console for vrnetlab-backed nodes.
	//
	// This covers most nodes launched via netlab/clabernetes that wrap a NOS with
	// vrnetlab (vMX, vJunos, ASAv, NX-OS, etc).
	if (rawCommand == "" || strings.EqualFold(rawCommand, "sh") || strings.EqualFold(rawCommand, "cli")) && pod != nil {
		image := ""
		for _, c := range pod.Spec.Containers {
			if strings.TrimSpace(c.Name) == container {
				image = strings.TrimSpace(c.Image)
				break
			}
		}
		if terminalutil.IsVrnetlabImage(image) {
			command = terminalutil.VrnetlabDefaultCommand(image)
			cmd = strings.Fields(command)
		} else if strings.EqualFold(rawCommand, "cli") {
			// `cli` isn't a standard binary in most containers; fall back to a shell.
			command = "sh"
			cmd = []string{"sh"}
		}
	}

	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}

	reqExec := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(k8sNamespace).
		SubResource("exec")
	reqExec.VersionedParams(opts, scheme.ParameterCodec)

	execURL := reqExec.URL()
	executor, err := remotecommand.NewSPDYExecutor(kcfg, http.MethodPost, execURL)
	if err != nil {
		_ = wsjson.Write(ctx, conn, terminalServerMsg{Type: "error", Data: "failed to start exec"})
		return
	}

	stdinR, stdinW := io.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	outCh := make(chan terminalServerMsg, 256)
	var outWg sync.WaitGroup
	outWg.Add(1)
	go func() {
		defer outWg.Done()
		for msg := range outCh {
			_ = wsjson.Write(ctx, conn, msg)
		}
	}()

	writeBytes := func(stream string) io.Writer {
		return writerFunc(func(p []byte) (int, error) {
			if len(p) == 0 {
				return 0, nil
			}
			outCh <- terminalServerMsg{Type: "output", Data: string(p), Stream: stream}
			return len(p), nil
		})
	}

	sizeQ := newTerminalSizeQueue()
	sizeQ.ch <- remotecommand.TerminalSize{Width: 120, Height: 35}

	// Reader loop: websocket -> stdin + resize.
	go func() {
		defer func() {
			_ = stdinW.Close()
		}()
		for {
			var in terminalClientMsg
			if err := wsjson.Read(ctx, conn, &in); err != nil {
				return
			}
			lastClientActivityUnixNano.Store(time.Now().UnixNano())
			switch strings.ToLower(strings.TrimSpace(in.Type)) {
			case "stdin":
				if in.Data == "" {
					continue
				}
				_, _ = io.WriteString(stdinW, in.Data)
			case "resize":
				if in.Cols == 0 || in.Rows == 0 {
					continue
				}
				select {
				case sizeQ.ch <- remotecommand.TerminalSize{Width: uint16(in.Cols), Height: uint16(in.Rows)}:
				default:
				}
			default:
			}
		}
	}()

	outCh <- terminalServerMsg{Type: "info", Data: fmt.Sprintf("connected: %s/%s (%s)", k8sNamespace, podName, strings.Join(cmd, " "))}
	if strings.HasPrefix(command, "telnet 127.0.0.1 5000") {
		outCh <- terminalServerMsg{Type: "info", Data: "vrnetlab console is single-connection; close other terminal windows for this node if you get disconnected."}
	}

	streamErr := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             stdinR,
		Stdout:            writeBytes("stdout"),
		Stderr:            writeBytes("stderr"),
		Tty:               true,
		TerminalSizeQueue: sizeQ,
	})
	close(outCh)
	outWg.Wait()

	if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
		rlog.Warn("terminal exec ended", "err", streamErr)
	}
}

type writerFunc func(p []byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }
