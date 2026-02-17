package skyforge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"encore.app/integrations/gitea"
)

var (
	giteaClientMu  sync.Mutex
	giteaClientCfg gitea.Config
	giteaClient    *gitea.Client
)

func giteaClientFor(cfg Config) *gitea.Client {
	giteaClientMu.Lock()
	defer giteaClientMu.Unlock()

	next := gitea.Config{
		APIURL:      cfg.UserContexts.GiteaAPIURL,
		Username:    cfg.UserContexts.GiteaUsername,
		Password:    cfg.UserContexts.GiteaPassword,
		Timeout:     15 * time.Second,
		RepoPrivate: cfg.UserContexts.GiteaRepoPrivate,
	}

	if giteaClient == nil || giteaClientCfg != next {
		giteaClientCfg = next
		giteaClient = gitea.New(next)
	}
	return giteaClient
}

func giteaClientForVisibility(cfg Config, repoPrivate bool) *gitea.Client {
	next := gitea.Config{
		APIURL:      cfg.UserContexts.GiteaAPIURL,
		Username:    cfg.UserContexts.GiteaUsername,
		Password:    cfg.UserContexts.GiteaPassword,
		Timeout:     15 * time.Second,
		RepoPrivate: repoPrivate,
	}
	return gitea.New(next)
}

func ensureGiteaUserFromProfile(cfg Config, profile *UserProfile) error {
	if profile == nil {
		return fmt.Errorf("missing user profile")
	}
	username := strings.TrimSpace(profile.Username)
	if username == "" {
		return fmt.Errorf("missing username")
	}
	identity := gitea.Identity(profile.DisplayName, username, profile.Email, cfg.CorpEmailDomain)
	email, _ := identity["email"].(string)
	name, _ := identity["name"].(string)
	if err := giteaClientFor(cfg).EnsureUser(username, email, name); err != nil {
		if strings.Contains(err.Error(), "e-mail already in use") {
			if giteaUserExists(cfg, username) {
				return nil
			}
			return fmt.Errorf("gitea email already in use for %s; resolve and retry", email)
		}
		return err
	}
	return nil
}

func ensureGiteaUser(cfg Config, username, password string) error {
	base := cfg.GiteaBaseURL
	apiURL := strings.TrimRight(cfg.UserContexts.GiteaAPIURL, "/")
	if apiURL != "" {
		if strings.HasSuffix(strings.ToLower(apiURL), "/api/v1") {
			base = strings.TrimSuffix(apiURL, "/api/v1")
		} else {
			base = apiURL
		}
	}
	base = normalizeGiteaBaseURL(ssoBaseURLOrDefault(base, ""))
	if strings.TrimSpace(base) == "" {
		return fmt.Errorf("gitea base url not configured")
	}
	loginURL := strings.TrimRight(base, "/") + "/user/login"

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar}
	getResp, err := client.Get(loginURL)
	if err != nil {
		return err
	}
	bodyBytes, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("gitea login page failed (%d)", getResp.StatusCode)
	}

	form := url.Values{}
	form.Set("user_name", username)
	form.Set("password", password)
	if token := extractFormValue(string(bodyBytes), "_csrf"); token != "" {
		form.Set("_csrf", token)
	}
	postReq, err := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp, err := client.Do(postReq)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, postResp.Body)
	_ = postResp.Body.Close()
	if postResp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("gitea login failed (%d)", postResp.StatusCode)
	}
	return nil
}

func ensureGiteaUserPassword(cfg Config, username, displayName, email, password string) error {
	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	email = strings.TrimSpace(email)
	if username == "" {
		return fmt.Errorf("gitea user missing username")
	}
	if email == "" {
		identity := gitea.Identity(displayName, username, email, cfg.CorpEmailDomain)
		if name, ok := identity["name"].(string); ok && strings.TrimSpace(name) != "" {
			displayName = strings.TrimSpace(name)
		}
		if derived, ok := identity["email"].(string); ok && strings.TrimSpace(derived) != "" {
			email = strings.TrimSpace(derived)
		}
	}
	if err := giteaClientFor(cfg).EnsureUser(username, email, displayName); err != nil {
		if strings.Contains(err.Error(), "e-mail already in use") {
			if !giteaUserExists(cfg, username) {
				return fmt.Errorf("gitea email already in use for %s; resolve and retry", email)
			}
		} else {
			return err
		}
	}
	return giteaClientFor(cfg).SetUserPassword(username, password)
}

func giteaUserExists(cfg Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	resp, _, err := giteaClientFor(cfg).Do(http.MethodGet, fmt.Sprintf("/users/%s", url.PathEscape(username)), nil)
	return err == nil && resp.StatusCode == http.StatusOK
}

func fallbackGiteaEmail(cfg Config, username string) string {
	domain := strings.TrimSpace(cfg.CorpEmailDomain)
	if domain == "" {
		domain = "local"
	}
	return fmt.Sprintf("%s+gitea@%s", username, domain)
}

func giteaDo(cfg Config, method, path string, payload any) (*http.Response, []byte, error) {
	return giteaClientFor(cfg).Do(method, path, payload)
}

func getGiteaRepoDefaultBranch(cfg Config, owner, repo string) (string, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		return "", fmt.Errorf("missing owner or repo")
	}

	if !envDisableEncoreCache() {
		if caches := getEncoreCachesSafe(); caches != nil {
			cacheKey := giteaDefaultBranchKey{Owner: owner, Repo: repo}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			cached, err := caches.giteaDefaultBranch.Get(ctx, cacheKey)
			cancel()
			if err == nil && strings.TrimSpace(cached) != "" {
				return strings.TrimSpace(cached), nil
			}
		}
	}

	branch, err := giteaClientFor(cfg).GetRepoDefaultBranch(owner, repo)
	if err != nil {
		return "", err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}

	if !envDisableEncoreCache() {
		if caches := getEncoreCachesSafe(); caches != nil {
			cacheKey := giteaDefaultBranchKey{Owner: owner, Repo: repo}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = caches.giteaDefaultBranch.Set(ctx, cacheKey, branch)
			cancel()
		}
	}

	return branch, nil
}

type giteaContentEntry = gitea.ContentEntry

type giteaDirCacheEntry struct {
	expires time.Time
	entries []giteaContentEntry
}

var giteaDirCache = struct {
	mu    sync.Mutex
	items map[string]giteaDirCacheEntry
}{
	items: make(map[string]giteaDirCacheEntry),
}

func listGiteaDirectory(cfg Config, owner, repo, dir, ref string) ([]giteaContentEntry, error) {
	cacheKey := strings.Join([]string{owner, repo, strings.TrimPrefix(dir, "/"), ref}, "|")
	now := time.Now()
	giteaDirCache.mu.Lock()
	if entry, ok := giteaDirCache.items[cacheKey]; ok && now.Before(entry.expires) {
		copied := make([]giteaContentEntry, len(entry.entries))
		copy(copied, entry.entries)
		giteaDirCache.mu.Unlock()
		return copied, nil
	}
	giteaDirCache.mu.Unlock()

	entries, err := giteaClientFor(cfg).ListDirectory(owner, repo, dir, ref)
	if err != nil {
		return nil, err
	}
	out := make([]giteaContentEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, giteaContentEntry(entry))
	}
	giteaDirCache.mu.Lock()
	giteaDirCache.items[cacheKey] = giteaDirCacheEntry{
		expires: now.Add(30 * time.Second),
		entries: out,
	}
	giteaDirCache.mu.Unlock()
	return out, nil
}

type giteaContentResponse struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Path     string `json:"path"`
}

type giteaBranchResponse struct {
	Name   string `json:"name"`
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
}

func getGiteaBranchHeadSHA(cfg Config, owner, repo, branch string) (string, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	branch = strings.TrimSpace(branch)
	if owner == "" || repo == "" || branch == "" {
		return "", fmt.Errorf("gitea branch lookup requires owner/repo/branch")
	}
	path := fmt.Sprintf("/repos/%s/%s/branches/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(branch))
	resp, body, err := giteaDo(cfg, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		fullURL := strings.TrimRight(cfg.UserContexts.GiteaAPIURL, "/") + path
		return "", fmt.Errorf("gitea %s responded %d: %s", fullURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed giteaBranchResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	sha := strings.TrimSpace(parsed.Commit.ID)
	if sha == "" {
		return "", fmt.Errorf("gitea branch commit id missing")
	}
	return sha, nil
}

func readGiteaFile(cfg Config, owner, repo, filePath, ref string) (string, error) {
	filePath = strings.TrimPrefix(strings.TrimSpace(filePath), "/")
	refSuffix := ""
	if strings.TrimSpace(ref) != "" {
		refSuffix = "?ref=" + url.QueryEscape(ref)
	}
	resp, body, err := giteaDo(cfg, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(filePath), refSuffix), nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gitea read file failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed giteaContentResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if parsed.Type != "file" {
		return "", fmt.Errorf("gitea content is not a file: %s", filePath)
	}
	content := parsed.Content
	if strings.EqualFold(parsed.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return content, nil
}

func readGiteaFileBytes(cfg Config, owner, repo, filePath, ref string) ([]byte, error) {
	filePath = strings.TrimPrefix(strings.TrimSpace(filePath), "/")
	refSuffix := ""
	if strings.TrimSpace(ref) != "" {
		refSuffix = "?ref=" + url.QueryEscape(ref)
	}
	resp, body, err := giteaDo(cfg, http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(filePath), refSuffix), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitea read file failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed giteaContentResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if parsed.Type != "file" {
		return nil, fmt.Errorf("gitea content is not a file: %s", filePath)
	}
	content := parsed.Content
	if strings.EqualFold(parsed.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return []byte(content), nil
}

func parseGiteaBlueprintSlug(blueprint string) (string, string, bool) {
	blueprint = strings.TrimSpace(blueprint)
	if blueprint == "" {
		return "", "", false
	}
	if strings.Contains(blueprint, "://") {
		parsed, err := url.Parse(blueprint)
		if err != nil {
			return "", "", false
		}
		segment := strings.Trim(parsed.Path, "/")
		if after, ok := strings.CutPrefix(segment, "git/"); ok {
			segment = after
		}
		segment = strings.TrimSuffix(segment, ".git")
		parts := strings.Split(segment, "/")
		if len(parts) < 2 {
			return "", "", false
		}
		return parts[len(parts)-2], parts[len(parts)-1], true
	}
	segment := strings.Trim(strings.TrimPrefix(blueprint, "/"), "/")
	if after, ok := strings.CutPrefix(segment, "git/"); ok {
		segment = after
	}
	segment = strings.TrimSuffix(segment, ".git")
	parts := strings.Split(segment, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[len(parts)-2], parts[len(parts)-1], true
}

func ensureBlueprintCatalogRepo(cfg Config, blueprint string) error {
	owner, repo, ok := parseGiteaBlueprintSlug(blueprint)
	if !ok {
		return nil
	}
	// The shared blueprint catalog should always be visible to users in Gitea Explore.
	// Workspace repos can remain private-by-default, but the catalog is intended for browsing.
	if err := ensureGiteaRepo(cfg, owner, repo, false); err != nil {
		return err
	}
	readme := "# Skyforge Blueprint Catalog\n\nThis repository contains validated deployment blueprints synced into user userContexts.\n"
	_ = ensureGiteaFile(cfg, owner, repo, "README.md", readme, "docs: add blueprint catalog README", "main", nil)

	// Ensure the catalog always contains at least one Containerlab topology so the
	// UI can list templates even before admins add their own.
	smoke := strings.TrimSpace(`name: skyforge-c9s-smoke

topology:
  nodes:
    r1:
      kind: linux
      image: alpine:3.20
      cmd: "sleep infinity"
    r2:
      kind: linux
      image: alpine:3.20
      cmd: "sleep infinity"
  links:
    - endpoints: ["r1:eth1", "r2:eth1"]
`) + "\n"
	_ = ensureGiteaFile(cfg, owner, repo, "containerlab/smoke.clab.yml", smoke, "chore: add containerlab smoke topology", "main", nil)

	// Skyforge's E2E device-matrix tests rely on these netlab templates existing in the
	// blueprints catalog repo (source=blueprints). They are intentionally small.
	netlabMinimal := strings.TrimSpace(`---
# Minimal topology used by Skyforge E2E tests.
#
# Notes:
# - Skyforge supplies NETLAB_DEVICE to override the device type at runtime,
#   allowing the same minimal topology to validate each supported platform.
# - Keep this topology intentionally small to reduce boot time and cluster load.
provider: clab

defaults:
  device: eos

nodes:
  r1: {}
  r2: {}

links:
  # Use the simplest netlab link syntax to avoid YAML-map ambiguity.
  - r1-r2
`) + "\n"
	_ = ensureGiteaFile(cfg, owner, repo, "netlab/_e2e/minimal/topology.yml", netlabMinimal, "test: add netlab minimal e2e topology", "main", nil)

	netlabOspf := strings.TrimSpace(`name: e2e-ospf

module: [ospf]

defaults:
  device: eos
  provider: clab

nodes:
  r1: {}
  r2: {}

links:
  - r1-r2
`) + "\n"
	_ = ensureGiteaFile(cfg, owner, repo, "netlab/_e2e/routing-ospf/topology.yml", netlabOspf, "test: add netlab ospf e2e topology", "main", nil)

	// Use explicit IPv4 p2p pool to avoid devices that can't do EBGP over IPv6 LLAs.
	netlabBgp := strings.TrimSpace(`name: e2e-bgp

module: [bgp]

defaults:
  device: eos
  provider: clab
  bgp:
    as: 65000

addressing:
  p2p:
    ipv4: 198.18.0.0/16

nodes:
  r1:
    bgp:
      as: 65100
  r2:
    bgp:
      as: 65200

links:
  - r1-r2
`) + "\n"
	_ = ensureGiteaFile(cfg, owner, repo, "netlab/_e2e/routing-bgp/topology.yml", netlabBgp, "test: add netlab bgp e2e topology", "main", nil)
	return nil
}

func syncGiteaRepoFromBlueprintWithSource(sourceCfg, targetCfg Config, targetOwner, targetRepo, blueprint string, targetBranch string, claims *SessionClaims) error {
	owner, repo, ok := parseGiteaBlueprintSlug(blueprint)
	if !ok {
		return fmt.Errorf("unsupported blueprint repo format")
	}
	blueprintBranch, err := getGiteaRepoDefaultBranch(sourceCfg, owner, repo)
	if err != nil {
		return err
	}
	if strings.TrimSpace(targetBranch) == "" {
		targetBranch = "main"
	}
	return syncGiteaDirectoryWithSource(sourceCfg, targetCfg, owner, repo, targetOwner, targetRepo, "", blueprintBranch, targetBranch, claims)
}

func syncBlueprintCatalogIntoUserContextRepo(sourceCfg, targetCfg Config, targetOwner, targetRepo, blueprint, targetBranch string, claims *SessionClaims) error {
	sourceOwner, sourceRepo, ok := parseGiteaBlueprintSlug(blueprint)
	if !ok {
		return fmt.Errorf("unsupported blueprint repo format")
	}
	sourceBranch, err := getGiteaRepoDefaultBranch(sourceCfg, sourceOwner, sourceRepo)
	if err != nil {
		return err
	}
	if strings.TrimSpace(targetBranch) == "" {
		targetBranch = "main"
	}

	// Copy the catalog into a subdirectory in the user's repo so it doesn't pollute the root.
	// The deployment UX expects `blueprints/<type>` (user-context repo), while the catalog repo is
	// `<type>` at the repo root.
	destRoot := "blueprints"
	expected := []string{"containerlab", "netlab", "terraform"}
	for _, dir := range expected {
		if err := syncGiteaDirectoryWithSourceToTarget(sourceCfg, targetCfg, sourceOwner, sourceRepo, targetOwner, targetRepo, dir, path.Join(destRoot, dir), sourceBranch, targetBranch, claims); err != nil {
			return err
		}
	}
	return nil
}

func syncGiteaDirectoryWithSource(sourceCfg, targetCfg Config, sourceOwner, sourceRepo, targetOwner, targetRepo, dir, sourceRef, targetBranch string, claims *SessionClaims) error {
	entries, err := listGiteaDirectory(sourceCfg, sourceOwner, sourceRepo, dir, sourceRef)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		entryPath := entry.Path
		if entryPath == "" {
			entryPath = path.Join(dir, entry.Name)
		}
		switch entry.Type {
		case "dir":
			if err := syncGiteaDirectoryWithSource(sourceCfg, targetCfg, sourceOwner, sourceRepo, targetOwner, targetRepo, entryPath, sourceRef, targetBranch, claims); err != nil {
				return err
			}
		case "file":
			content, err := readGiteaFile(sourceCfg, sourceOwner, sourceRepo, entryPath, sourceRef)
			if err != nil {
				return err
			}
			if err := ensureGiteaFile(targetCfg, targetOwner, targetRepo, entryPath, content, "sync: "+entryPath, targetBranch, claims); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncGiteaDirectoryWithSourceToTarget(sourceCfg, targetCfg Config, sourceOwner, sourceRepo, targetOwner, targetRepo, sourceDir, targetDir, sourceRef, targetBranch string, claims *SessionClaims) error {
	entries, err := listGiteaDirectory(sourceCfg, sourceOwner, sourceRepo, sourceDir, sourceRef)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		entryPath := entry.Path
		if entryPath == "" {
			entryPath = path.Join(sourceDir, entry.Name)
		}
		targetPath := path.Join(targetDir, entry.Name)
		switch entry.Type {
		case "dir":
			if err := syncGiteaDirectoryWithSourceToTarget(sourceCfg, targetCfg, sourceOwner, sourceRepo, targetOwner, targetRepo, entryPath, targetPath, sourceRef, targetBranch, claims); err != nil {
				return err
			}
		case "file":
			content, err := readGiteaFile(sourceCfg, sourceOwner, sourceRepo, entryPath, sourceRef)
			if err != nil {
				return err
			}
			if err := ensureGiteaFile(targetCfg, targetOwner, targetRepo, targetPath, content, "sync: "+targetPath, targetBranch, claims); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureGiteaRepo(cfg Config, owner, repo string, repoPrivate bool) error {
	client := giteaClientForVisibility(cfg, repoPrivate)
	if err := client.EnsureRepo(owner, repo); err != nil {
		return err
	}
	// If the repo already existed (possibly with the wrong visibility), enforce it explicitly.
	return client.SetRepoPrivate(owner, repo, repoPrivate)
}

func ensureGiteaRepoFromBlueprint(cfg Config, owner, repo, blueprint string, repoPrivate bool) error {
	// For Skyforge MVP we avoid copying blueprint content into each user-context repo.
	// Projects can reference the shared blueprint catalog directly for deployments.
	// A manual "sync" can be added later if/when users want a forked copy.
	return ensureGiteaRepo(cfg, owner, repo, repoPrivate)
}

func giteaIdentityFromClaims(cfg Config, claims *SessionClaims) map[string]any {
	if claims == nil {
		return nil
	}
	return gitea.Identity(claims.DisplayName, claims.Username, claims.Email, cfg.CorpEmailDomain)
}

func ensureGiteaFile(cfg Config, owner, repo, filePath, content, message, branch string, claims *SessionClaims) error {
	return giteaClientFor(cfg).EnsureFile(owner, repo, filePath, content, message, branch, giteaIdentityFromClaims(cfg, claims))
}

func ensureGiteaCollaborator(cfg Config, owner, repo, username, permission string) error {
	return giteaClientFor(cfg).EnsureCollaborator(owner, repo, username, permission)
}

func removeGiteaCollaborator(cfg Config, owner, repo, username string) error {
	return giteaClientFor(cfg).RemoveCollaborator(owner, repo, username)
}

func purgeGiteaUser(ctx context.Context, cfg Config, username string) error {
	_ = ctx
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	client := giteaClientFor(cfg)
	repos, err := client.ListUserRepos(username)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		owner := strings.TrimSpace(repo.Owner.Login)
		name := strings.TrimSpace(repo.Name)
		if owner == "" || name == "" {
			continue
		}
		if err := client.DeleteRepo(owner, name); err != nil {
			return err
		}
	}
	return client.DeleteUser(username)
}

func listGiteaCollaborators(cfg Config, owner, repo string) ([]string, error) {
	return giteaClientFor(cfg).ListCollaborators(owner, repo)
}
