package skyforge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func checkServiceNowPDI(ctx context.Context, instanceURL, adminUsername, adminPassword string) (status string, httpStatus int, detail string) {
	base := strings.TrimRight(strings.TrimSpace(instanceURL), "/")
	if base == "" {
		return "unknown", 0, "missing instance url"
	}
	_, err := url.Parse(base)
	if err != nil {
		return "unknown", 0, "invalid instance url"
	}

	target := base + "/api/now/table/sys_user?sysparm_limit=1"

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Preserve redirect responses so we can classify "sleeping" vs "auth".
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "unknown", 0, "request build failed"
	}
	req.SetBasicAuth(adminUsername, adminPassword)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if isTimeoutErr(err) {
			return "unreachable", 0, "timeout"
		}
		return "unreachable", 0, "request failed"
	}
	defer resp.Body.Close()

	httpStatus = resp.StatusCode
	bodySnippet := readSnippet(resp.Body, 8192)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	lowerBody := strings.ToLower(bodySnippet)

	// Auth / permissions
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "auth_failed", resp.StatusCode, "unauthorized"
	}

	// PDI sleeping often returns 503/504 or an HTML "waking up" page.
	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		return "sleeping", resp.StatusCode, "service unavailable"
	}
	if strings.Contains(lowerBody, "hibernat") || strings.Contains(lowerBody, "waking") || strings.Contains(lowerBody, "starting") {
		// Heuristic: ServiceNow uses "hibernating" for sleeping PDIs.
		return "sleeping", resp.StatusCode, "pdi appears to be sleeping"
	}

	// Redirects can happen when the instance is waking or presenting a login gateway.
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusTemporaryRedirect {
		loc := resp.Header.Get("Location")
		if loc != "" {
			return "sleeping", resp.StatusCode, "redirect: " + loc
		}
		return "sleeping", resp.StatusCode, "redirect"
	}

	// Success path.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// If we got JSON, assume awake even if body parsing fails later.
		if strings.Contains(contentType, "application/json") || strings.Contains(lowerBody, "\"result\"") {
			return "awake", resp.StatusCode, ""
		}
		// Some instances can reply HTML via SSO; treat as unknown but reachable.
		return "unknown", resp.StatusCode, "unexpected content-type"
	}

	// Everything else: unknown, but reachable.
	return "unknown", resp.StatusCode, "unexpected status"
}

func triggerServiceNowPDIWake(ctx context.Context, instanceURL string) error {
	base := strings.TrimRight(strings.TrimSpace(instanceURL), "/")
	if base == "" {
		return errors.New("missing instance url")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

func readSnippet(r io.Reader, max int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, max))
	return string(b)
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}
