package skyforge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type DNSTokenResponse struct {
	Token string `json:"token"`
	Zone  string `json:"zone,omitempty"`
}

type DNSBootstrapRequest struct {
	Password string `json:"password,omitempty"`
}

type DNSBootstrapResponse struct {
	Token string `json:"token"`
	Zone  string `json:"zone"`
}

type technitiumTokenEnvelope struct {
	Status       string `json:"status"`
	Token        string `json:"token,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	Message      string `json:"message,omitempty"`
	Response     struct {
		Token string `json:"token,omitempty"`
	} `json:"response,omitempty"`
}

func (t technitiumTokenEnvelope) extractToken() string {
	if strings.TrimSpace(t.Token) != "" {
		return strings.TrimSpace(t.Token)
	}
	if strings.TrimSpace(t.Response.Token) != "" {
		return strings.TrimSpace(t.Response.Token)
	}
	return ""
}

func (s *Service) technitiumBaseURL() string {
	base := strings.TrimSpace(s.cfg.DNSURL)
	if base == "" {
		base = "http://technitium-dns:5380"
	}
	return strings.TrimRight(base, "/")
}

func (s *Service) technitiumAdminUsername() string {
	if v := strings.TrimSpace(s.cfg.DNSAdminUsername); v != "" {
		return v
	}
	return "admin"
}

func (s *Service) technitiumAdminPassword() string {
	// Reuse the shared Skyforge admin password so we don't need extra secrets.
	return strings.TrimSpace(s.cfg.AdminPassword)
}

func (s *Service) mintTechnitiumAdminToken(ctx context.Context) (string, error) {
	password := s.technitiumAdminPassword()
	if password == "" {
		return "", errs.B().Code(errs.FailedPrecondition).Msg("dns sso not configured").Err()
	}

	form := url.Values{}
	form.Set("user", s.technitiumAdminUsername())
	form.Set("pass", password)
	form.Set("totp", "")
	form.Set("includeInfo", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.technitiumBaseURL()+"/api/user/login", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("failed to build dns login request").Err()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("failed to reach dns service").Err()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return "", errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("dns login failed (%d)", resp.StatusCode)).Err()
	}

	var decoded technitiumTokenEnvelope
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("dns login returned invalid response").Err()
	}
	token := decoded.extractToken()
	if token == "" {
		return "", errs.B().Code(errs.Unavailable).Msg("dns login returned invalid response").Err()
	}
	return token, nil
}

func (s *Service) technitiumRequest(ctx context.Context, endpoint string, params url.Values) ([]byte, error) {
	reqURL := s.technitiumBaseURL() + endpoint
	if params != nil && len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}

func technitiumStatus(body []byte) (string, map[string]any, string) {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", nil, ""
	}
	status, _ := decoded["status"].(string)
	resp, _ := decoded["response"].(map[string]any)
	msg, _ := decoded["errorMessage"].(string)
	if strings.TrimSpace(msg) == "" {
		msg, _ = decoded["message"].(string)
	}
	return strings.TrimSpace(status), resp, strings.TrimSpace(msg)
}

func (s *Service) ensureTechnitiumUserAndZone(ctx context.Context, adminToken, username, displayName, password, zone string) error {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	zone = strings.TrimSpace(zone)
	if username == "" || password == "" || zone == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("missing dns bootstrap parameters").Err()
	}
	if !isValidUsername(username) {
		return errs.B().Code(errs.InvalidArgument).Msg("invalid username").Err()
	}

	call := func(endpoint string, extra url.Values) error {
		params := url.Values{}
		params.Set("token", adminToken)
		for k, v := range extra {
			for _, item := range v {
				params.Add(k, item)
			}
		}
		body, err := s.technitiumRequest(ctx, endpoint, params)
		if err != nil {
			return err
		}
		status, _, msg := technitiumStatus(body)
		if strings.EqualFold(status, "ok") {
			return nil
		}
		if msg == "" {
			msg = "request failed"
		}
		return fmt.Errorf("%s: %s", endpoint, msg)
	}

	// Ensure user exists; update/reset password every time (the caller just provided it).
	{
		body, err := s.technitiumRequest(ctx, "/api/admin/users/get", url.Values{
			"token": []string{adminToken},
			"user":  []string{username},
		})
		if err != nil {
			return err
		}
		status, _, _ := technitiumStatus(body)
		if strings.EqualFold(status, "ok") {
			extra := url.Values{
				"user":    []string{username},
				"newPass": []string{password},
			}
			if strings.TrimSpace(displayName) != "" {
				extra.Set("displayName", strings.TrimSpace(displayName))
			}
			if err := call("/api/admin/users/set", extra); err != nil {
				return err
			}
		} else {
			extra := url.Values{
				"user": []string{username},
				"pass": []string{password},
			}
			if strings.TrimSpace(displayName) != "" {
				extra.Set("displayName", strings.TrimSpace(displayName))
			}
			if err := call("/api/admin/users/create", extra); err != nil {
				return err
			}
		}
	}

	// Ensure zone exists.
	{
		body, err := s.technitiumRequest(ctx, "/api/zones/create", url.Values{
			"token": []string{adminToken},
			"zone":  []string{zone},
			"type":  []string{"Primary"},
		})
		if err != nil {
			return err
		}
		status, _, msg := technitiumStatus(body)
		if strings.EqualFold(status, "ok") {
			// created
		} else if strings.Contains(strings.ToLower(msg), "exist") {
			// already exists
		} else {
			if msg == "" {
				msg = "failed to create zone"
			}
			return fmt.Errorf("zones/create: %s", msg)
		}
	}

	// Ensure zone permissions include this user.
	{
		permBody, err := s.technitiumRequest(ctx, "/api/zones/permissions/get", url.Values{
			"token":                 []string{adminToken},
			"zone":                  []string{zone},
			"includeUsersAndGroups": []string{"true"},
		})
		if err != nil {
			return err
		}
		_, resp, _ := technitiumStatus(permBody)
		userRows := []string{}
		groupRows := []string{}

		if rows, ok := resp["userPermissions"].([]any); ok {
			for _, row := range rows {
				m, _ := row.(map[string]any)
				u, _ := m["username"].(string)
				canView, _ := m["canView"].(bool)
				canModify, _ := m["canModify"].(bool)
				canDelete, _ := m["canDelete"].(bool)
				if strings.EqualFold(strings.TrimSpace(u), username) {
					continue
				}
				if strings.TrimSpace(u) == "" {
					continue
				}
				userRows = append(userRows, fmt.Sprintf("%s|%t|%t|%t", strings.TrimSpace(u), canView, canModify, canDelete))
			}
		}
		// Append current user.
		userRows = append(userRows, fmt.Sprintf("%s|true|true|true", username))

		if rows, ok := resp["groupPermissions"].([]any); ok {
			for _, row := range rows {
				m, _ := row.(map[string]any)
				n, _ := m["name"].(string)
				canView, _ := m["canView"].(bool)
				canModify, _ := m["canModify"].(bool)
				canDelete, _ := m["canDelete"].(bool)
				if strings.TrimSpace(n) == "" {
					continue
				}
				groupRows = append(groupRows, fmt.Sprintf("%s|%t|%t|%t", strings.TrimSpace(n), canView, canModify, canDelete))
			}
		}

		extra := url.Values{
			"zone": []string{zone},
		}
		if len(userRows) > 0 {
			extra.Set("userPermissions", strings.Join(userRows, "|"))
		}
		if len(groupRows) > 0 {
			extra.Set("groupPermissions", strings.Join(groupRows, "|"))
		}
		if err := call("/api/zones/permissions/set", extra); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) technitiumCreateUserToken(ctx context.Context, username, password string) (string, error) {
	body, err := s.technitiumRequest(ctx, "/api/user/createToken", url.Values{
		"user":      []string{strings.TrimSpace(username)},
		"pass":      []string{strings.TrimSpace(password)},
		"tokenName": []string{"Skyforge"},
	})
	if err != nil {
		return "", err
	}
	var decoded technitiumTokenEnvelope
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("invalid response")
	}
	token := decoded.extractToken()
	if token == "" {
		return "", fmt.Errorf("token missing")
	}
	return token, nil
}

func randomTechnitiumPassword() (string, error) {
	// Use a hex-encoded random value to avoid special characters that some setups reject.
	// 24 bytes => 48 hex chars + prefix.
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "sf-" + hex.EncodeToString(buf), nil
}

// DNSToken mints a Technitium session token for the current Skyforge user session.
// The token is stored client-side (localStorage) by the DNS SSO bridge.
//
//encore:api auth method=GET path=/api/dns/token
func (s *Service) DNSToken(ctx context.Context) (*DNSTokenResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	rec, err := s.getDNSToken(ctx, user.Username)
	if err != nil {
		return nil, err
	}
	if rec == nil || strings.TrimSpace(rec.Token) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("dns setup required").Err()
	}
	return &DNSTokenResponse{Token: rec.Token, Zone: rec.Zone}, nil
}

// DNSBootstrap provisions a per-user Technitium account + zone and stores a long-lived API token in Skyforge.
//
// This enables "SSO" without needing to store or reuse the user's password.
//
//encore:api auth method=POST path=/api/dns/bootstrap
func (s *Service) DNSBootstrap(ctx context.Context, req *DNSBootstrapRequest) (*DNSBootstrapResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}

	username := strings.ToLower(strings.TrimSpace(user.Username))
	if !isValidUsername(username) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid username").Err()
	}

	suffix := strings.TrimSpace(s.cfg.DNSUserZoneSuffix)
	if suffix == "" {
		suffix = "skyforge"
	}
	suffix = strings.TrimPrefix(suffix, ".")
	zone := username + "." + suffix

	password := ""
	if req != nil {
		password = strings.TrimSpace(req.Password)
	}
	if password == "" {
		password, err = randomTechnitiumPassword()
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to generate dns password").Err()
		}
	}

	adminToken, err := s.mintTechnitiumAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.ensureTechnitiumUserAndZone(ctx, adminToken, username, strings.TrimSpace(user.DisplayName), password, zone); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to provision dns account").Err()
	}
	token, err := s.technitiumCreateUserToken(ctx, username, password)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to mint dns token").Err()
	}
	if err := s.putDNSToken(ctx, username, token, zone); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store dns token").Err()
	}
	return &DNSBootstrapResponse{Token: token, Zone: zone}, nil
}

// DNSSSO bridges Skyforge auth into Technitium DNS by storing a minted token in localStorage and redirecting.
//
// NOTE: Technitium uses localStorage tokens (not cookies). This endpoint serves a tiny HTML page that:
//  1. fetches a token from Skyforge Server
//  2. stores it in localStorage
//  3. redirects to /dns/
//
//encore:api auth raw method=GET path=/api/dns/sso
func (s *Service) DNSSSO(w http.ResponseWriter, r *http.Request) {
	user, err := requireAuthUser()
	if err != nil {
		s.redirectToReauth(w, r)
		return
	}

	next := strings.TrimSpace(r.URL.Query().Get("next"))
	if next == "" {
		next = "/dns/"
	}
	// Only allow local redirects under /dns to avoid open redirects.
	if !strings.HasPrefix(next, "/dns") {
		next = "/dns/"
	}
	if next == "/dns" {
		next = "/dns/"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	escapedNext := html.EscapeString(next)
	username := strings.ToLower(strings.TrimSpace(user.Username))
	suffix := strings.TrimSpace(s.cfg.DNSUserZoneSuffix)
	if suffix == "" {
		suffix = "skyforge"
	}
	suffix = strings.TrimPrefix(suffix, ".")
	zone := username + "." + suffix
	escapedZone := html.EscapeString(zone)

	page := `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="referrer" content="no-referrer" />
    <meta http-equiv="cache-control" content="no-store" />
    <title>DNS SSO</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; padding: 24px; }
      .card { max-width: 520px; border: 1px solid rgba(255,255,255,0.12); border-radius: 10px; padding: 16px; }
      button { margin-top: 12px; padding: 10px 12px; border-radius: 8px; border: 0; background: #2563eb; color: white; font-weight: 600; cursor: pointer; }
      .muted { font-size: 12px; opacity: 0.75; margin-top: 8px; }
      .error { color: #ef4444; margin-top: 10px; font-size: 13px; }
      .hidden { display: none; }
    </style>
  </head>
  <body>
    <div class="card">
      <h3 style="margin:0 0 6px 0;">DNS</h3>
      <p id="status" style="margin:0 0 10px 0;">Signing you into DNS…</p>
      <div id="setup" class="hidden">
        <p class="muted" style="margin:0 0 10px 0;">
          Setting up DNS SSO for <code>` + escapedZone + `</code>…
        </p>
        <button id="skip" type="button" style="background:#475569;">Continue without SSO</button>
        <div id="err" class="error hidden"></div>
      </div>
    </div>
    <script>
      (async () => {
        try {
          const resp = await fetch("/api/skyforge/api/dns/token", { cache: "no-store", credentials: "include" });
          if (resp.ok) {
            const data = await resp.json();
            if (data && data.token) {
              localStorage.setItem("token", String(data.token));
              window.location.replace("` + escapedNext + `");
              return;
            }
          }
          document.getElementById("status").textContent = "DNS setup required";
          document.getElementById("setup").classList.remove("hidden");
          const skip = document.getElementById("skip");
          const err = document.getElementById("err");
          const showErr = (msg) => { err.textContent = msg; err.classList.remove("hidden"); };
          skip.addEventListener("click", () => window.location.replace("` + escapedNext + `"));
          try {
            const r = await fetch("/api/skyforge/api/dns/bootstrap", {
              method: "POST",
              credentials: "include",
              headers: { "content-type": "application/json" },
              body: "{}"
            });
            if (!r.ok) throw new Error(await r.text());
            const out = await r.json();
            if (!out || !out.token) throw new Error("Missing token.");
            localStorage.setItem("token", String(out.token));
            window.location.replace("` + escapedNext + `");
          } catch (e) {
            showErr(String(e && e.message ? e.message : e));
            document.getElementById("status").textContent = "DNS setup failed";
          }
        } catch (e) {
          window.location.replace("` + escapedNext + `");
        }
      })();
    </script>
    <noscript>
      <p>JavaScript is required to complete DNS SSO. Continue to <a href="` + escapedNext + `">DNS</a>.</p>
    </noscript>
  </body>
</html>`

	_, _ = w.Write([]byte(page))
}
