package skyforge

import (
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
		APIURL:      cfg.Projects.GiteaAPIURL,
		Username:    cfg.Projects.GiteaUsername,
		Password:    cfg.Projects.GiteaPassword,
		Timeout:     15 * time.Second,
		RepoPrivate: cfg.Projects.GiteaRepoPrivate,
	}

	if giteaClient == nil || giteaClientCfg != next {
		giteaClientCfg = next
		giteaClient = gitea.New(next)
	}
	return giteaClient
}

func ensureGiteaUser(cfg Config, username, password string) error {
	base := cfg.GiteaBaseURL
	apiURL := strings.TrimRight(cfg.Projects.GiteaAPIURL, "/")
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

func giteaDo(cfg Config, method, path string, payload any) (*http.Response, []byte, error) {
	return giteaClientFor(cfg).Do(method, path, payload)
}

func getGiteaRepoDefaultBranch(cfg Config, owner, repo string) (string, error) {
	return giteaClientFor(cfg).GetRepoDefaultBranch(owner, repo)
}

type giteaContentEntry = gitea.ContentEntry

func listGiteaDirectory(cfg Config, owner, repo, dir, ref string) ([]giteaContentEntry, error) {
	entries, err := giteaClientFor(cfg).ListDirectory(owner, repo, dir, ref)
	if err != nil {
		return nil, err
	}
	out := make([]giteaContentEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, giteaContentEntry(entry))
	}
	return out, nil
}

type giteaContentResponse struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Path     string `json:"path"`
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
		if strings.HasPrefix(segment, "git/") {
			segment = strings.TrimPrefix(segment, "git/")
		}
		segment = strings.TrimSuffix(segment, ".git")
		parts := strings.Split(segment, "/")
		if len(parts) < 2 {
			return "", "", false
		}
		return parts[len(parts)-2], parts[len(parts)-1], true
	}
	segment := strings.Trim(strings.TrimPrefix(blueprint, "/"), "/")
	if strings.HasPrefix(segment, "git/") {
		segment = strings.TrimPrefix(segment, "git/")
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
	if err := ensureGiteaRepo(cfg, owner, repo); err != nil {
		return err
	}
	readme := "# Skyforge Blueprint Catalog\n\nThis repository contains validated deployment blueprints synced into user projects.\n"
	_ = ensureGiteaFile(cfg, owner, repo, "README.md", readme, "docs: add blueprint catalog README", "main", nil)
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

func ensureGiteaRepo(cfg Config, owner, repo string) error {
	return giteaClientFor(cfg).EnsureRepo(owner, repo)
}

func ensureGiteaRepoFromBlueprint(cfg Config, owner, repo, blueprint string) error {
	// For Skyforge MVP we avoid copying blueprint content into each project repo.
	// Projects can reference the shared blueprint catalog directly for deployments.
	// A manual "sync" can be added later if/when users want a forked copy.
	return giteaClientFor(cfg).EnsureRepo(owner, repo)
}

func giteaIdentityFromClaims(claims *SessionClaims) map[string]any {
	if claims == nil {
		return nil
	}
	return gitea.Identity(claims.DisplayName, claims.Username, claims.Email)
}

func ensureGiteaFile(cfg Config, owner, repo, filePath, content, message, branch string, claims *SessionClaims) error {
	return giteaClientFor(cfg).EnsureFile(owner, repo, filePath, content, message, branch, giteaIdentityFromClaims(claims))
}

func ensureGiteaCollaborator(cfg Config, owner, repo, username, permission string) error {
	return giteaClientFor(cfg).EnsureCollaborator(owner, repo, username, permission)
}

func removeGiteaCollaborator(cfg Config, owner, repo, username string) error {
	return giteaClientFor(cfg).RemoveCollaborator(owner, repo, username)
}

func listGiteaCollaborators(cfg Config, owner, repo string) ([]string, error) {
	return giteaClientFor(cfg).ListCollaborators(owner, repo)
}
