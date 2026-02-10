package taskengine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"encore.app/integrations/gitea"
)

type templateRepoRef struct {
	Owner  string
	Repo   string
	Branch string
}

var netlabBundleLock = struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}{
	locks: map[string]*sync.Mutex{},
}

func withNetlabBundleLock(key string, fn func() error) error {
	netlabBundleLock.mu.Lock()
	lock := netlabBundleLock.locks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		netlabBundleLock.locks[key] = lock
	}
	netlabBundleLock.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func isSafeRelativePath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for part := range strings.SplitSeq(value, "/") {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func parseGiteaRepoRef(input string) (string, string, error) {
	ref := strings.TrimSpace(input)
	if ref == "" {
		return "", "", fmt.Errorf("repo is required")
	}
	if strings.Contains(ref, "://") {
		u, err := url.Parse(ref)
		if err != nil {
			return "", "", fmt.Errorf("invalid repo url")
		}
		ref = strings.Trim(strings.TrimPrefix(u.Path, "/"), "/")
	}
	parts := strings.Split(strings.Trim(ref, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("repo must be of form owner/repo")
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

func defaultNetlabTemplatesDir(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
		return "netlab"
	default:
		return "blueprints/netlab"
	}
}

func normalizeNetlabTemplatesDir(source, dir string) string {
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	if dir == "" {
		dir = defaultNetlabTemplatesDir(source)
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
		dir = strings.TrimPrefix(dir, "blueprints/")
	}
	return strings.Trim(strings.TrimSpace(dir), "/")
}

func normalizeNetlabTemplateSelectionWithSource(source, templatesDir, templateFile string) (string, string, string) {
	templatesDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
	templateFile = strings.TrimSpace(templateFile)
	if templatesDir == "" {
		templatesDir = defaultNetlabTemplatesDir(source)
	}
	templatesDir = normalizeNetlabTemplatesDir(source, templatesDir)
	if strings.HasSuffix(templatesDir, ".yml") || strings.HasSuffix(templatesDir, ".yaml") {
		base := path.Base(templatesDir)
		if templateFile == "" || templateFile == base {
			templateFile = base
		}
		templatesDir = strings.Trim(strings.TrimSpace(path.Dir(templatesDir)), "/")
	}
	templatePath := strings.TrimPrefix(path.Join(templatesDir, templateFile), "/")
	return templatesDir, templateFile, templatePath
}

func (e *Engine) giteaClient() *gitea.Client {
	return gitea.New(gitea.Config{
		APIURL:      strings.TrimRight(strings.TrimSpace(e.cfg.Workspaces.GiteaAPIURL), "/"),
		Username:    strings.TrimSpace(e.cfg.Workspaces.GiteaUsername),
		Password:    strings.TrimSpace(e.cfg.Workspaces.GiteaPassword),
		Timeout:     20 * time.Second,
		RepoPrivate: true,
	})
}

func (e *Engine) giteaDefaultBranch(owner, repo string) string {
	branch := "main"
	client := e.giteaClient()
	if client == nil {
		return branch
	}
	if b, err := client.GetRepoDefaultBranch(owner, repo); err == nil && strings.TrimSpace(b) != "" {
		branch = strings.TrimSpace(b)
	}
	return branch
}

func (e *Engine) resolveTemplateRepoForWorkspace(pc *workspaceContext, source string, customRepo string) (templateRepoRef, error) {
	if pc == nil {
		return templateRepoRef{}, fmt.Errorf("workspace context unavailable")
	}
	owner := strings.TrimSpace(pc.workspace.GiteaOwner)
	repo := strings.TrimSpace(pc.workspace.GiteaRepo)
	branch := strings.TrimSpace(pc.workspace.DefaultBranch)

	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "workspace":
		// default
	case "blueprints", "blueprint":
		ref := strings.TrimSpace(pc.workspace.Blueprint)
		if ref == "" {
			ref = "skyforge/blueprints"
		}
		parts := strings.Split(strings.Trim(ref, "/"), "/")
		if len(parts) < 2 {
			return templateRepoRef{}, fmt.Errorf("blueprints repo must be of form owner/repo")
		}
		owner, repo = parts[0], parts[1]
		branch = ""
	case "external":
		if !pc.workspace.AllowExternalTemplateRepos {
			return templateRepoRef{}, fmt.Errorf("external template repos are not enabled for this workspace")
		}
		repoID := strings.TrimSpace(customRepo)
		if repoID == "" {
			return templateRepoRef{}, fmt.Errorf("external repo id is required")
		}
		var found *ExternalTemplateRepo
		for i := range pc.workspace.ExternalTemplateRepos {
			if strings.TrimSpace(pc.workspace.ExternalTemplateRepos[i].ID) == repoID {
				found = &pc.workspace.ExternalTemplateRepos[i]
				break
			}
		}
		if found == nil {
			return templateRepoRef{}, fmt.Errorf("unknown external template repo")
		}
		parts := strings.Split(strings.Trim(strings.TrimSpace(found.Repo), "/"), "/")
		if len(parts) < 2 {
			return templateRepoRef{}, fmt.Errorf("external repo must be of form owner/repo")
		}
		owner, repo = parts[0], parts[1]
		branch = strings.TrimSpace(found.DefaultBranch)
	case "custom":
		if !pc.workspace.AllowExternalTemplateRepos {
			return templateRepoRef{}, fmt.Errorf("custom template repos are not enabled for this workspace")
		}
		customOwner, customName, err := parseGiteaRepoRef(customRepo)
		if err != nil {
			return templateRepoRef{}, err
		}
		owner, repo = customOwner, customName
		branch = ""
	default:
		return templateRepoRef{}, fmt.Errorf("unknown template source")
	}

	if branch == "" {
		branch = e.giteaDefaultBranch(owner, repo)
	}
	return templateRepoRef{Owner: owner, Repo: repo, Branch: branch}, nil
}

func (e *Engine) listGiteaDirectory(owner, repo, dir, ref string) ([]gitea.ContentEntry, error) {
	client := e.giteaClient()
	if client == nil {
		return nil, fmt.Errorf("gitea client unavailable")
	}
	return client.ListDirectory(owner, repo, dir, ref)
}

func (e *Engine) readGiteaFileBytes(ctx context.Context, owner, repo, filePath, ref string) ([]byte, error) {
	client := e.giteaClient()
	if client == nil {
		return nil, fmt.Errorf("gitea client unavailable")
	}
	filePath = strings.TrimPrefix(strings.TrimSpace(filePath), "/")
	if filePath == "" {
		return nil, fmt.Errorf("file path is required")
	}
	pathURL := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(filePath))
	if strings.TrimSpace(ref) != "" {
		pathURL += "?ref=" + url.QueryEscape(ref)
	}
	resp, body, err := client.Do(http.MethodGet, pathURL, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitea contents failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, fmt.Errorf("gitea contents path is a directory (%s)", filePath)
	}
	var parsed struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(parsed.Encoding), "base64") {
		return nil, fmt.Errorf("unsupported gitea encoding")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(parsed.Content, "\n", ""))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// buildNetlabTopologyBundleB64 packages the selected netlab template directory into a tar.gz and
// base64-encodes it for the netlab API server.
//
// The bundle root is flattened: the template directory contents are written at the tar root, and
// the selected topology is renamed to topology.yml.
func (e *Engine) buildNetlabTopologyBundleB64(ctx context.Context, pc *workspaceContext, templateSource, templateRepo, templatesDir, templateFile string) (string, error) {
	if e == nil {
		return "", fmt.Errorf("engine unavailable")
	}
	if pc == nil {
		return "", fmt.Errorf("workspace context unavailable")
	}
	templatesDir, templateFile, templatePath := normalizeNetlabTemplateSelectionWithSource(templateSource, templatesDir, templateFile)
	if templateFile == "" {
		return "", fmt.Errorf("netlab template is required")
	}
	if !isSafeRelativePath(templatesDir) {
		return "", fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	ref, err := e.resolveTemplateRepoForWorkspace(pc, templateSource, templateRepo)
	if err != nil {
		return "", err
	}
	templatePath = strings.TrimPrefix(path.Join(templatesDir, templateFile), "/")
	if templatePath == "" {
		return "", fmt.Errorf("template path is required")
	}

	templateDir := strings.Trim(strings.TrimSpace(path.Dir(templatePath)), "/")
	if templateDir == "" || templateDir == "." {
		templateDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
	}
	if templateDir == "" {
		return "", fmt.Errorf("template dir is required")
	}

	lockKey := strings.Join([]string{ref.Owner, ref.Repo, ref.Branch, templateDir, templatePath}, "|")
	var out string
	if err := withNetlabBundleLock(lockKey, func() error {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		written := map[string]bool{}
		defer func() {
			_ = tw.Close()
			_ = gz.Close()
		}()

		var walkDir func(repoDir string, stripPrefix string, renameTopology bool) error
		walkDir = func(repoDir string, stripPrefix string, renameTopology bool) error {
			entries, err := e.listGiteaDirectory(ref.Owner, ref.Repo, repoDir, ref.Branch)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("netlab template directory is empty: %s", repoDir)
			}
			for _, entry := range entries {
				name := strings.TrimSpace(entry.Name)
				if name == "" || strings.HasPrefix(name, ".") {
					continue
				}
				entryPath := strings.TrimPrefix(strings.TrimSpace(entry.Path), "/")
				switch entry.Type {
				case "dir":
					if err := walkDir(entryPath, stripPrefix, renameTopology); err != nil {
						return err
					}
				case "file":
					data, err := e.readGiteaFileBytes(ctx, ref.Owner, ref.Repo, entryPath, ref.Branch)
					if err != nil {
						return err
					}
					rel := strings.TrimPrefix(entryPath, stripPrefix)
					rel = strings.TrimPrefix(rel, "/")
					tarName := rel
					if renameTopology && entryPath == templatePath {
						tarName = "topology.yml"
					}
					tarName = path.Clean(strings.TrimPrefix(tarName, "/"))
					if tarName == "." || tarName == "" || strings.HasPrefix(tarName, "..") {
						continue
					}
					if written[tarName] {
						continue
					}
					hdr := &tar.Header{
						Name:    tarName,
						Mode:    0o644,
						Size:    int64(len(data)),
						ModTime: time.Now(),
					}
					if err := tw.WriteHeader(hdr); err != nil {
						return err
					}
					if _, err := tw.Write(data); err != nil {
						return err
					}
					written[tarName] = true
				default:
					continue
				}
			}
			return nil
		}

		if err := walkDir(templateDir, templateDir, true); err != nil {
			return err
		}

		// Include Skyforge "overlay" files (shared across templates) if present.
		// This is used for netlab custom config templates (e.g., snmp_config) and other shared assets.
		overlayRoot := strings.Trim(strings.TrimSpace(templatesDir), "/")
		if overlayRoot != "" && overlayRoot != "." {
			overlayDir := strings.TrimPrefix(path.Join(overlayRoot, "_skyforge"), "/")
			if overlayDir != "" {
				if entries, err := e.listGiteaDirectory(ref.Owner, ref.Repo, overlayDir, ref.Branch); err == nil && len(entries) > 0 {
					if err := walkDir(overlayDir, overlayDir, false); err != nil {
						return err
					}
				}
			}
		}

		if err := tw.Close(); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		out = base64.StdEncoding.EncodeToString(buf.Bytes())
		return nil
	}); err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("netlab topology bundle is empty")
	}
	return out, nil
}
