package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type templateRepoRef struct {
	Owner  string
	Repo   string
	Branch string
}

var netlabSyncLock = struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}{
	locks: make(map[string]*sync.Mutex),
}

func withNetlabSyncLock(key string, fn func() error) error {
	netlabSyncLock.mu.Lock()
	lock, ok := netlabSyncLock.locks[key]
	if !ok {
		lock = &sync.Mutex{}
		netlabSyncLock.locks[key] = lock
	}
	netlabSyncLock.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func defaultLabppTemplatesDir(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint":
		return "labpp"
	default:
		return "blueprints/labpp"
	}
}

func normalizeLabppTemplatesDir(source, dir string) string {
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	if dir == "" {
		dir = defaultLabppTemplatesDir(source)
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint":
		dir = strings.TrimPrefix(dir, "blueprints/")
	}
	return strings.Trim(strings.TrimSpace(dir), "/")
}

func giteaDefaultBranch(cfg Config, owner, repo string) string {
	branch := "main"
	if b, err := getGiteaRepoDefaultBranch(cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
		branch = strings.TrimSpace(b)
	}
	return branch
}

func defaultNetlabTemplatesDir(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint":
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
	case "blueprints", "blueprint":
		dir = strings.TrimPrefix(dir, "blueprints/")
	}
	return strings.Trim(strings.TrimSpace(dir), "/")
}

func normalizeNetlabTemplateSelectionWithSource(source, templatesDir, templateFile string) (string, string, string, string) {
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
	rootPath := strings.TrimPrefix(templatesDir, "/")
	if strings.HasPrefix(rootPath, "netlab/") || rootPath == "netlab" {
		rootPath = "netlab"
	} else if idx := strings.Index(rootPath, "/netlab/"); idx >= 0 {
		rootPath = rootPath[:idx+len("/netlab")]
	}
	rootPath = strings.TrimSuffix(rootPath, "/")
	if rootPath == "" || rootPath == "." {
		rootPath = strings.TrimPrefix(templatesDir, "/")
	}
	topologyPath := ""
	if templateFile != "" {
		templatePath := strings.TrimPrefix(path.Join(templatesDir, templateFile), "/")
		rel := strings.TrimPrefix(templatePath, rootPath)
		rel = strings.TrimPrefix(rel, "/")
		if rel != "" {
			topologyPath = path.Join("netlab", rel)
		}
	}
	return templatesDir, templateFile, rootPath, topologyPath
}

func normalizeNetlabTemplateSelection(templatesDir, templateFile string) (string, string, string, string) {
	return normalizeNetlabTemplateSelectionWithSource("workspace", templatesDir, templateFile)
}

func (s *Service) syncNetlabTopologyFile(ctx context.Context, pc *workspaceContext, server *NetlabServerConfig, templateSource, templateRepo, templatesDir, templateFile, workdir, owner string) (string, error) {
	if server == nil {
		return "", fmt.Errorf("netlab runner not configured")
	}
	templatesDir, templateFile, rootPath, topologyPath := normalizeNetlabTemplateSelectionWithSource(templateSource, templatesDir, templateFile)
	if templateFile == "" {
		return "", nil
	}
	if !isSafeRelativePath(templatesDir) {
		return "", fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	ref, err := resolveTemplateRepoForProject(s.cfg, pc, templateSource, templateRepo)
	if err != nil {
		return "", err
	}

	sshCfg := NetlabConfig{
		SSHHost:    strings.TrimSpace(server.SSHHost),
		SSHUser:    strings.TrimSpace(server.SSHUser),
		SSHKeyFile: strings.TrimSpace(server.SSHKeyFile),
		StateRoot:  "/",
	}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return "", err
	}
	defer client.Close()

	destRoot := path.Join(workdir, "netlab")
	if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", destRoot), 10*time.Second); err != nil {
		return "", err
	}

	// Preserve the full directory layout under the netlab root, but avoid syncing more than needed.
	// When a template lives in a subdirectory (e.g. blueprints/netlab/<template>/...), syncing only
	// that subtree is much faster than syncing the whole netlab folder.
	syncStartPath := rootPath
	if templatesDir != "" && templatesDir != rootPath {
		syncStartPath = templatesDir
	}

	lockKey := strings.Join([]string{workdir, ref.Owner, ref.Repo, ref.Branch, rootPath}, "|")
	if err := withNetlabSyncLock(lockKey, func() error {
		// If the repo hasn't changed since last sync, avoid re-copying the entire netlab directory.
		// This makes consecutive create→start runs fast and also prevents redundant syncs when
		// multiple netlab tasks are queued close together.
		sha := ""
		if ref.Owner != "" && ref.Repo != "" && ref.Branch != "" {
			if got, err := getGiteaBranchHeadSHA(s.cfg, ref.Owner, ref.Repo, ref.Branch); err == nil {
				sha = strings.TrimSpace(got)
			}
		}
		stampPath := path.Join(destRoot, ".skyforge-netlab-sync")
		if sha != "" && topologyPath != "" {
			required := path.Join(workdir, topologyPath)
			current, _ := runSSHCommand(client, fmt.Sprintf("cat %q 2>/dev/null || true", stampPath), 5*time.Second)
			current = strings.TrimSpace(current)
			expected := strings.TrimSpace(strings.Join([]string{
				"repo=" + ref.Owner + "/" + ref.Repo,
				"branch=" + ref.Branch,
				"sha=" + sha,
				"root=" + rootPath,
			}, "\n"))
			existsOut, _ := runSSHCommand(client, fmt.Sprintf("test -f %q && echo ok || true", required), 5*time.Second)
			if strings.TrimSpace(existsOut) == "ok" && current == expected {
				return nil
			}
		}

		var syncDir func(repoPath string) error
		syncDir = func(repoPath string) error {
			entries, err := listGiteaDirectory(s.cfg, ref.Owner, ref.Repo, repoPath, ref.Branch)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("netlab template directory is empty: %s", repoPath)
			}
			for _, entry := range entries {
				name := strings.TrimSpace(entry.Name)
				if name == "" || strings.HasPrefix(name, ".") {
					continue
				}
				entryPath := strings.TrimPrefix(strings.TrimSpace(entry.Path), "/")
				rel := strings.TrimPrefix(entryPath, rootPath)
				rel = strings.TrimPrefix(rel, "/")
				dest := path.Join(destRoot, rel)
				switch entry.Type {
				case "dir":
					if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", dest), 10*time.Second); err != nil {
						return err
					}
					if err := syncDir(entryPath); err != nil {
						return err
					}
				case "file":
					body, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, entryPath, ref.Branch)
					if err != nil {
						return fmt.Errorf("failed to read template %s: %w", entryPath, err)
					}
					if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", path.Dir(dest)), 10*time.Second); err != nil {
						return err
					}
					writeCmd := fmt.Sprintf("cat > %q", dest)
					if _, err := runSSHCommandWithInput(client, writeCmd, body, 15*time.Second); err != nil {
						return err
					}
					_, _ = runSSHCommand(client, fmt.Sprintf("chmod 0644 %q >/dev/null 2>&1 || true", dest), 5*time.Second)
				}
			}
			return nil
		}

		syncedViaArchive := false
		// Fast path: download the repo archive once and extract only the needed subtree.
		// This avoids a large number of per-file API calls + SSH round-trips which can add 30-60s.
		{
			apiURL := strings.TrimRight(strings.TrimSpace(s.cfg.Workspaces.GiteaAPIURL), "/")
			user := strings.TrimSpace(s.cfg.Workspaces.GiteaUsername)
			pass := strings.TrimSpace(s.cfg.Workspaces.GiteaPassword)
			if apiURL != "" && user != "" && pass != "" && ref.Owner != "" && ref.Repo != "" && ref.Branch != "" {
				archiveURL := fmt.Sprintf(
					"%s/repos/%s/%s/archive/%s.tar.gz",
					apiURL,
					url.PathEscape(ref.Owner),
					url.PathEscape(ref.Repo),
					url.PathEscape(ref.Branch),
				)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
				if err == nil {
					req.SetBasicAuth(user, pass)
					resp, err := http.DefaultClient.Do(req)
					if err == nil && resp != nil {
						defer resp.Body.Close()
						if resp.StatusCode == http.StatusOK {
							stripComponents := 1 + strings.Count(strings.Trim(rootPath, "/"), "/") + 1
							pattern := fmt.Sprintf("*/%s/*", strings.Trim(syncStartPath, "/"))
							cmd := fmt.Sprintf("tar -xzf - -C %q --strip-components=%d --wildcards %q", destRoot, stripComponents, pattern)
							if _, err := runSSHCommandWithReader(client, cmd, resp.Body, 4*time.Minute); err == nil {
								syncedViaArchive = true
							}
						} else {
							_, _ = io.Copy(io.Discard, resp.Body)
						}
					}
				}
			}
		}

		if !syncedViaArchive {
			if err := syncDir(syncStartPath); err != nil {
				return err
			}
		}

		templatePath := strings.TrimPrefix(path.Join(templatesDir, templateFile), "/")
		if templatePath != "" {
			if _, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, templatePath, ref.Branch); err != nil {
				return fmt.Errorf("failed to read template %s: %w", templatePath, err)
			}
		}
		if sha != "" {
			expected := strings.TrimSpace(strings.Join([]string{
				"repo=" + ref.Owner + "/" + ref.Repo,
				"branch=" + ref.Branch,
				"sha=" + sha,
				"root=" + rootPath,
			}, "\n"))
			// Use a heredoc to avoid complex quoting/escaping.
			writeCmd := fmt.Sprintf("cat > %q <<'__SKYFORGE__'\n%s\n__SKYFORGE__\n", stampPath, expected)
			_, _ = runSSHCommand(client, writeCmd, 5*time.Second)
		}
		return nil
	}); err != nil {
		return "", err
	}

	if owner != "" {
		_, _ = runSSHCommand(client, fmt.Sprintf("chown -R %q:%q %q >/dev/null 2>&1 || true", owner, owner, workdir), 8*time.Second)
	}
	return topologyPath, nil
}

func resolveTemplateRepoForProject(cfg Config, pc *workspaceContext, source string, customRepo string) (templateRepoRef, error) {
	owner := pc.workspace.GiteaOwner
	repo := pc.workspace.GiteaRepo
	branch := strings.TrimSpace(pc.workspace.DefaultBranch)

	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "workspace":
		// default
	case "blueprints", "blueprint":
		ref := strings.TrimSpace(pc.workspace.Blueprint)
		if ref == "" {
			ref = "skyforge/blueprints"
		}
		if strings.Contains(ref, "://") {
			if u, err := url.Parse(ref); err == nil {
				ref = strings.Trim(strings.TrimPrefix(u.Path, "/"), "/")
			}
		}
		parts := strings.Split(strings.Trim(ref, "/"), "/")
		if len(parts) < 2 {
			return templateRepoRef{}, fmt.Errorf("blueprints repo must be of form owner/repo")
		}
		owner, repo = parts[0], parts[1]
		branch = ""
	case "custom":
		customOwner, customName, err := parseGiteaRepoRef(customRepo)
		if err != nil {
			return templateRepoRef{}, err
		}
		if !isAdminUser(cfg, pc.claims.Username) && customOwner != pc.workspace.GiteaOwner && customOwner != "skyforge" {
			return templateRepoRef{}, fmt.Errorf("custom repo not allowed")
		}
		owner, repo = customOwner, customName
		branch = ""
	default:
		return templateRepoRef{}, fmt.Errorf("unknown template source")
	}

	if branch == "" {
		branch = giteaDefaultBranch(cfg, owner, repo)
	}
	return templateRepoRef{Owner: owner, Repo: repo, Branch: branch}, nil
}

func (s *Service) syncLabppTemplateDir(ctx context.Context, pc *workspaceContext, eveServer *EveServerConfig, templateSource, templateRepo, templatesDir, templateName, destRoot string) (string, error) {
	templateName = strings.TrimSpace(templateName)
	if templateName == "" {
		return "", fmt.Errorf("template is required")
	}
	templatesDir = normalizeLabppTemplatesDir(templateSource, templatesDir)
	if !isSafeRelativePath(templatesDir) {
		return "", fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	if strings.TrimSpace(destRoot) == "" {
		destRoot = "/var/lib/skyforge/labpp/templates"
	}
	destRoot = strings.TrimRight(strings.TrimSpace(destRoot), "/")
	destTemplateDir := filepath.Join(destRoot, templateName)

	ref, err := resolveTemplateRepoForProject(s.cfg, pc, templateSource, templateRepo)
	if err != nil {
		return "", err
	}

	host := strings.TrimSpace(eveServer.SSHHost)
	if host == "" && strings.TrimSpace(eveServer.APIURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(eveServer.APIURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" && strings.TrimSpace(eveServer.WebURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(eveServer.WebURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" {
		return "", fmt.Errorf("missing eve server host for labpp template sync")
	}

	rootPath := path.Join(templatesDir, templateName)
	labJSONPath := path.Join(rootPath, "lab.json")
	if _, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, labJSONPath, ref.Branch); err != nil {
		return "", fmt.Errorf("labpp template %q missing lab.json", templateName)
	}
	log.Printf("labpp template sync: repo=%s/%s branch=%s root=%s dest=%s", ref.Owner, ref.Repo, ref.Branch, rootPath, destTemplateDir)
	rootEntries, err := listGiteaDirectory(s.cfg, ref.Owner, ref.Repo, rootPath, ref.Branch)
	if err != nil {
		return "", fmt.Errorf("failed to list labpp template %q: %w", templateName, err)
	}
	if len(rootEntries) == 0 {
		return "", fmt.Errorf("labpp template %q has no files under %s", templateName, rootPath)
	}

	if err := os.RemoveAll(destTemplateDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(destTemplateDir, 0o755); err != nil {
		return "", err
	}

	var syncDir func(repoPath string) error
	syncDir = func(repoPath string) error {
		entries, err := listGiteaDirectory(s.cfg, ref.Owner, ref.Repo, repoPath, ref.Branch)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := strings.TrimSpace(entry.Name)
			if name == "" || strings.HasPrefix(name, ".") {
				continue
			}
			entryPath := strings.TrimPrefix(strings.TrimSpace(entry.Path), "/")
			rel := strings.TrimPrefix(entryPath, rootPath)
			rel = strings.TrimPrefix(rel, "/")
			dest := path.Join(destTemplateDir, rel)
			switch entry.Type {
			case "dir":
				if err := os.MkdirAll(dest, 0o755); err != nil {
					return err
				}
				if err := syncDir(entryPath); err != nil {
					return err
				}
			case "file":
				body, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, entryPath, ref.Branch)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(path.Dir(dest), 0o755); err != nil {
					return err
				}
				if strings.HasSuffix(entryPath, "/lab.json") {
					body = injectLabppServer(body, host)
				}
				if err := os.WriteFile(dest, body, 0o644); err != nil {
					return err
				}
			default:
				// ignore
			}
		}
		return nil
	}

	if err := syncDir(rootPath); err != nil {
		log.Printf("labpp template sync failed: %v", err)
		return "", fmt.Errorf("failed to sync labpp template")
	}
	_ = ctx
	return destRoot, nil
}

func (s *Service) labppTemplateExists(eveServer *EveServerConfig, templatesRoot, templateName string) (bool, error) {
	templatesRoot = strings.TrimRight(strings.TrimSpace(templatesRoot), "/")
	templateName = strings.TrimSpace(templateName)
	if templatesRoot == "" || templateName == "" {
		return false, fmt.Errorf("templatesRoot and template are required")
	}
	if _, err := os.Stat(filepath.Join(templatesRoot, templateName, "lab.json")); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func injectLabppServer(body []byte, host string) []byte {
	if strings.TrimSpace(host) == "" {
		return body
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	doc["labpp_server"] = host
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return body
	}
	return append(updated, '\n')
}
