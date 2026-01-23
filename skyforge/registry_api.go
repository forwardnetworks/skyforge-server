package skyforge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type registryRepoListResponse struct {
	Repositories []string `json:"repositories"`
}

type registryTagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type RegistryReposResponse struct {
	BaseURL       string   `json:"baseUrl,omitempty"`
	Repositories  []string `json:"repositories"`
	FilteredCount int      `json:"filteredCount"`
	TotalCount    int      `json:"totalCount"`
}

type RegistryTagsListResponse struct {
	Repository string   `json:"repository"`
	Tags       []string `json:"tags"`
}

type registryEnvConfig struct {
	BaseURL       string
	Username      string
	Password      string
	SkipTLSVerify bool
	RepoPrefixes  []string
}

func registryConfigFromEnv() registryEnvConfig {
	cfg := registryEnvConfig{
		BaseURL:  strings.TrimRight(strings.TrimSpace(os.Getenv("SKYFORGE_REGISTRY_URL")), "/"),
		Username: strings.TrimSpace(os.Getenv("SKYFORGE_REGISTRY_USERNAME")),
		Password: strings.TrimSpace(os.Getenv("SKYFORGE_REGISTRY_PASSWORD")),
	}
	if v := strings.TrimSpace(os.Getenv("SKYFORGE_REGISTRY_SKIP_TLS_VERIFY")); v != "" {
		cfg.SkipTLSVerify = strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if raw := strings.TrimSpace(os.Getenv("SKYFORGE_REGISTRY_REPO_PREFIXES")); raw != "" {
		parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ';' })
		for _, p := range parts {
			p = strings.Trim(strings.TrimSpace(p), "/")
			if p == "" {
				continue
			}
			cfg.RepoPrefixes = append(cfg.RepoPrefixes, p)
		}
	}
	return cfg
}

func registryHTTPClient(skipTLSVerify bool) *http.Client {
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}
	if skipTLSVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // user-configured
	}
	return &http.Client{Timeout: 8 * time.Second, Transport: tr}
}

func registryDoJSON(ctx context.Context, cfg registryEnvConfig, method, path string, out any) error {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return fmt.Errorf("registry not configured (set SKYFORGE_REGISTRY_URL)")
	}
	u := cfg.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if cfg.Username != "" || cfg.Password != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}

	resp, err := registryHTTPClient(cfg.SkipTLSVerify).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("registry request failed: %s", msg)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func hasAnyPrefix(repo string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	repo = strings.Trim(strings.ToLower(strings.TrimSpace(repo)), "/")
	for _, p := range prefixes {
		p = strings.Trim(strings.ToLower(strings.TrimSpace(p)), "/")
		if p == "" {
			continue
		}
		if repo == p || strings.HasPrefix(repo, p+"/") {
			return true
		}
	}
	return false
}

// ListRegistryRepos returns available repositories from the configured registry.
//
// Uses Docker Registry HTTP API v2 `_catalog`.
//
// Env:
// - SKYFORGE_REGISTRY_URL (required), e.g. https://ghcr.io
// - SKYFORGE_REGISTRY_USERNAME / SKYFORGE_REGISTRY_PASSWORD (optional)
// - SKYFORGE_REGISTRY_SKIP_TLS_VERIFY (optional: true/false)
// - SKYFORGE_REGISTRY_REPO_PREFIXES (optional comma-separated prefixes to include)
//
// Query:
// - q: substring match filter
// - n: server-side page size for _catalog
//
//encore:api auth raw method=GET path=/api/registry/repos
func (s *Service) ListRegistryRepos(w http.ResponseWriter, req *http.Request) {
	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := registryConfigFromEnv()
	if cfg.BaseURL == "" {
		http.Error(w, "registry not configured (set SKYFORGE_REGISTRY_URL)", http.StatusServiceUnavailable)
		return
	}

	q := strings.ToLower(strings.TrimSpace(req.URL.Query().Get("q")))
	n := 200
	if raw := strings.TrimSpace(req.URL.Query().Get("n")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 5000 {
			n = parsed
		}
	}

	var payload registryRepoListResponse
	path := fmt.Sprintf("/v2/_catalog?n=%d", n)
	if err := registryDoJSON(req.Context(), cfg, http.MethodGet, path, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	repos := make([]string, 0, len(payload.Repositories))
	for _, r := range payload.Repositories {
		r = strings.Trim(strings.TrimSpace(r), "/")
		if r == "" {
			continue
		}
		if !hasAnyPrefix(r, cfg.RepoPrefixes) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(r), q) {
			continue
		}
		repos = append(repos, r)
	}
	sort.Strings(repos)

	resp := RegistryReposResponse{
		BaseURL:       cfg.BaseURL,
		Repositories:  repos,
		FilteredCount: len(repos),
		TotalCount:    len(payload.Repositories),
	}
	writeJSON(w, http.StatusOK, resp)
}

// ListRegistryTags returns tags for a specific repository from the configured registry.
//
//encore:api auth raw method=GET path=/api/registry/repos/:repo/tags
func (s *Service) ListRegistryTags(w http.ResponseWriter, req *http.Request) {
	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := registryConfigFromEnv()
	if cfg.BaseURL == "" {
		http.Error(w, "registry not configured (set SKYFORGE_REGISTRY_URL)", http.StatusServiceUnavailable)
		return
	}

	repo := strings.Trim(strings.TrimSpace(req.PathValue("repo")), "/")
	if repo == "" {
		http.Error(w, "repo is required", http.StatusBadRequest)
		return
	}
	if !hasAnyPrefix(repo, cfg.RepoPrefixes) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload registryTagsResponse
	path := fmt.Sprintf("/v2/%s/tags/list", url.PathEscape(repo))
	if err := registryDoJSON(req.Context(), cfg, http.MethodGet, path, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	tags := make([]string, 0, len(payload.Tags))
	q := strings.ToLower(strings.TrimSpace(req.URL.Query().Get("q")))
	for _, t := range payload.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(t), q) {
			continue
		}
		tags = append(tags, t)
	}
	sort.Strings(tags)

	writeJSON(w, http.StatusOK, RegistryTagsListResponse{
		Repository: repo,
		Tags:       tags,
	})
}
