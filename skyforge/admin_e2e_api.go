package skyforge

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

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
