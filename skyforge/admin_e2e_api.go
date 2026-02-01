package skyforge

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"encore.dev"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

const e2eAdminTokenHeader = "X-Skyforge-E2E-Token"

type adminSSHProbeRequest struct {
	Hosts          []string `json:"hosts"`
	Port           int      `json:"port,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
}

type adminSSHProbeResult struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
}

type adminSSHProbeResponse struct {
	OK      bool                           `json:"ok"`
	Results map[string]adminSSHProbeResult `json:"results,omitempty"`
}

type adminE2ESessionRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName,omitempty"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`
}

type adminE2ESessionResponse struct {
	SetCookie string      `header:"Set-Cookie" json:"-"`
	Cookie    string      `json:"cookie"`
	User      UserProfile `json:"user"`
}

// AdminE2ESession seeds a session cookie for CI/E2E flows without external SSO.
//
// encore:api public method=POST path=/api/admin/e2e/session
func (s *Service) AdminE2ESession(ctx context.Context, req *adminE2ESessionRequest) (*adminE2ESessionResponse, error) {
	if s == nil || s.sessionManager == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("service unavailable").Err()
	}
	if err := s.requireE2EAdminToken(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = username
	}
	email := strings.TrimSpace(req.Email)
	if email == "" && strings.TrimSpace(s.cfg.CorpEmailDomain) != "" {
		email = fmt.Sprintf("%s@%s", username, strings.TrimSpace(s.cfg.CorpEmailDomain))
	}
	groups := normalizeE2EGroups(req.Groups, s.cfg.MaxGroups)

	profile := &UserProfile{
		Authenticated: true,
		Username:      username,
		DisplayName:   displayName,
		Email:         email,
		Groups:        groups,
		IsAdmin:       isAdminUser(s.cfg, username),
	}

	cookie, err := s.sessionManager.IssueCookieForHeaders(currentHeaders(), profile)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to create session").Err()
	}

	if s.userStore != nil {
		if err := s.userStore.upsert(username); err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to provision user").Err()
		}
	}
	if s.db != nil {
		writeAuditEvent(ctx, s.db, username, profile.IsAdmin, "", "auth.e2e.seed", "", auditDetailsFromEncore(encore.CurrentRequest()))
	}

	resp := &adminE2ESessionResponse{
		SetCookie: cookie.String(),
		Cookie:    cookie.String(),
		User:      *profile,
	}
	return resp, nil
}

func (s *Service) requireE2EAdminToken() error {
	if !s.cfg.E2EAdminEnabled {
		return errs.B().Code(errs.PermissionDenied).Msg("e2e admin api disabled").Err()
	}
	expected := strings.TrimSpace(s.cfg.E2EAdminToken)
	if expected == "" {
		return errs.B().Code(errs.FailedPrecondition).Msg("e2e admin token not configured").Err()
	}
	token := strings.TrimSpace(currentHeaders().Get(e2eAdminTokenHeader))
	if token == "" {
		return errs.B().Code(errs.Unauthenticated).Msg("missing e2e admin token").Err()
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return errs.B().Code(errs.PermissionDenied).Msg("invalid e2e admin token").Err()
	}
	return nil
}

func normalizeE2EGroups(groups []string, maxGroups int) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	seen := map[string]struct{}{}
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		key := strings.ToLower(group)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, group)
		if maxGroups > 0 && len(out) >= maxGroups {
			break
		}
	}
	sort.Strings(out)
	return out
}

// AdminSSHProbe runs an in-cluster TCP probe to validate SSH reachability of a list of hosts.
// This is primarily used by `cmd/e2echeck` so E2E tests can run without local kubectl access.
//
// NOTE: This does not authenticate to the target device; it only verifies TCP connect and an
// SSH-like banner prefix ("SSH-").
//
// encore:api auth method=POST path=/api/admin/e2e/sshprobe
func (s *Service) AdminSSHProbe(ctx context.Context, req *adminSSHProbeRequest) (*adminSSHProbeResponse, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	hosts := make([]string, 0, len(req.Hosts))
	seen := map[string]struct{}{}
	for _, h := range req.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("hosts required").Err()
	}
	sort.Strings(hosts)

	port := req.Port
	if port <= 0 {
		port = 22
	}
	if port > 65535 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid port").Err()
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	if timeout > 60*time.Minute {
		timeout = 60 * time.Minute
	}

	type result struct {
		ok       bool
		attempts int
		err      string
	}

	results := map[string]result{}
	var mu sync.Mutex

	ctxDeadline := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctxDeadline, cancel = context.WithTimeout(ctx, timeout+30*time.Second)
		defer cancel()
	}

	var wg sync.WaitGroup
	for _, host := range hosts {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(timeout)
			var lastErr string
			attempts := 0
			for time.Now().Before(deadline) {
				select {
				case <-ctxDeadline.Done():
					lastErr = "context canceled"
					mu.Lock()
					results[host] = result{ok: false, attempts: attempts, err: lastErr}
					mu.Unlock()
					return
				default:
				}

				attempts++
				addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
				d := net.Dialer{Timeout: 3 * time.Second}
				conn, err := d.DialContext(ctxDeadline, "tcp", addr)
				if err != nil {
					lastErr = err.Error()
					time.Sleep(2 * time.Second)
					continue
				}

				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 4)
				_, _ = conn.Read(buf)
				_ = conn.Close()

				if string(buf) == "SSH-" {
					mu.Lock()
					results[host] = result{ok: true, attempts: attempts}
					mu.Unlock()
					return
				}
				lastErr = fmt.Sprintf("bad banner prefix: %q", string(buf))
				time.Sleep(2 * time.Second)
			}
			mu.Lock()
			results[host] = result{ok: false, attempts: attempts, err: lastErr}
			mu.Unlock()
		}()
	}
	wg.Wait()

	out := &adminSSHProbeResponse{
		OK:      true,
		Results: map[string]adminSSHProbeResult{},
	}
	for _, h := range hosts {
		res := results[h]
		out.Results[h] = adminSSHProbeResult{
			OK:       res.ok,
			Error:    strings.TrimSpace(res.err),
			Attempts: res.attempts,
		}
		if !res.ok {
			out.OK = false
		}
	}

	if !out.OK {
		rlog.Warn("AdminSSHProbe failed", "hosts", hosts)
	}
	return out, nil
}
