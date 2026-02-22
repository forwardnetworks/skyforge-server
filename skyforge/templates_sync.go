package skyforge

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
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

func giteaDefaultBranch(cfg Config, owner, repo string) string {
	branch := "main"
	if b, err := getGiteaRepoDefaultBranch(cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
		branch = strings.TrimSpace(b)
	}
	return branch
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

func defaultContainerlabTemplatesDir(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
		return "containerlab"
	default:
		return "blueprints/containerlab"
	}
}

func defaultEveNgTemplatesDir(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
		return "eve-ng"
	default:
		return "blueprints/eve-ng"
	}
}

func normalizeContainerlabTemplatesDir(source, dir string) string {
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	if dir == "" {
		dir = defaultContainerlabTemplatesDir(source)
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
		dir = strings.TrimPrefix(dir, "blueprints/")
	}
	return strings.Trim(strings.TrimSpace(dir), "/")
}

func normalizeEveNgTemplatesDir(source, dir string) string {
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	if dir == "" {
		dir = defaultEveNgTemplatesDir(source)
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
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
	return normalizeNetlabTemplateSelectionWithSource("user", templatesDir, templateFile)
}

func (s *Service) syncNetlabTopologyFile(ctx context.Context, pc *userContext, server *NetlabServerConfig, templateSource, templateRepo, templatesDir, templateFile, workdir, owner string) (string, error) {
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
	policy, _ := loadGovernancePolicy(ctx, s.db)
	ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, templateSource, templateRepo)
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

	// For better operator ergonomics, copy the selected template directory contents into the
	// workdir root. This ensures users can `cd <workdir> && netlab up` without having to pass
	// a topology path or deal with nested `netlab/<template>` directories.
	destRoot := strings.TrimRight(strings.TrimSpace(workdir), "/")
	if destRoot == "" {
		return "", fmt.Errorf("workdir is required")
	}
	if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", destRoot), 10*time.Second); err != nil {
		return "", err
	}
	// Remove the nested sync directory to avoid confusing mixes of old + new layouts.
	_, _ = runSSHCommand(client, fmt.Sprintf("rm -rf %q >/dev/null 2>&1 || true", path.Join(destRoot, "netlab")), 30*time.Second)

	templatePath := strings.TrimPrefix(path.Join(templatesDir, templateFile), "/")
	if templatePath == "" {
		return "", fmt.Errorf("template path is required")
	}
	// Copy only the directory containing the selected topology file (and its children).
	// Example: templatesDir=netlab templateFile=EVPN/ebgp/topology.yml => templateDir=netlab/EVPN/ebgp
	templateDir := strings.Trim(strings.TrimSpace(path.Dir(templatePath)), "/")
	if templateDir == "" || templateDir == "." {
		templateDir = strings.Trim(strings.TrimSpace(rootPath), "/")
	}
	// We strip the template directory prefix so its contents land in the workdir root.
	stripPrefix := strings.Trim(strings.TrimSpace(templateDir), "/")
	syncStartPath := stripPrefix

	// The resulting topology file lives at the workdir root.
	topologyPath = path.Base(templateFile)
	if topologyPath == "" {
		topologyPath = "topology.yml"
	}

	lockKey := strings.Join([]string{workdir, ref.Owner, ref.Repo, ref.Branch, stripPrefix}, "|")
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
				"root=" + stripPrefix,
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
				rel := strings.TrimPrefix(entryPath, stripPrefix)
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
			apiURL := strings.TrimRight(strings.TrimSpace(s.cfg.UserScopes.GiteaAPIURL), "/")
			user := strings.TrimSpace(s.cfg.UserScopes.GiteaUsername)
			pass := strings.TrimSpace(s.cfg.UserScopes.GiteaPassword)
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
							trimmed := strings.Trim(syncStartPath, "/")
							stripComponents := 1
							if trimmed != "" {
								stripComponents += strings.Count(trimmed, "/") + 1
							}
							pattern := fmt.Sprintf("*/%s/*", trimmed)
							cmd := fmt.Sprintf("tar -xzf - -C %q --strip-components=%d --wildcards %q", destRoot, stripComponents, pattern)
							if _, err := runSSHCommandWithReader(client, cmd, resp.Body, 4*time.Minute); err == nil {
								// Some tar implementations can report success even if wildcard extraction
								// didn't produce the expected topology file; fall back to per-file sync in
								// that case to avoid confusing "topology.yml missing" failures later.
								required := path.Join(workdir, topologyPath)
								out, _ := runSSHCommand(client, fmt.Sprintf("test -f %q && echo ok || true", required), 5*time.Second)
								if strings.TrimSpace(out) == "ok" {
									syncedViaArchive = true
								} else {
									log.Printf("netlab archive sync did not produce %s; falling back to per-file sync", required)
								}
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

		// Ensure the selected topology file is present at the workdir root (the netlab runner expects this).
		required := path.Join(workdir, topologyPath)
		out, _ := runSSHCommand(client, fmt.Sprintf("test -f %q && echo ok || true", required), 5*time.Second)
		if strings.TrimSpace(out) != "ok" {
			return fmt.Errorf("synced topology file missing: %s", required)
		}

		// Validate that the selected topology exists in the source repo and should now exist in the workdir root.
		if _, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, strings.TrimPrefix(path.Join(templatesDir, templateFile), "/"), ref.Branch); err != nil {
			return fmt.Errorf("failed to read template %s: %w", strings.TrimPrefix(path.Join(templatesDir, templateFile), "/"), err)
		}
		if sha != "" {
			expected := strings.TrimSpace(strings.Join([]string{
				"repo=" + ref.Owner + "/" + ref.Repo,
				"branch=" + ref.Branch,
				"sha=" + sha,
				"root=" + stripPrefix,
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

func (s *Service) buildNetlabTopologyBundleB64(ctx context.Context, pc *userContext, templateSource, templateRepo, templatesDir, templateFile string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("service unavailable")
	}
	if pc == nil {
		return "", fmt.Errorf("user context unavailable")
	}
	templatesDir, templateFile, rootPath, _ := normalizeNetlabTemplateSelectionWithSource(templateSource, templatesDir, templateFile)
	if templateFile == "" {
		return "", nil
	}
	if !isSafeRelativePath(templatesDir) {
		return "", fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	policy, _ := loadGovernancePolicy(ctx, s.db)
	ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, templateSource, templateRepo)
	if err != nil {
		return "", err
	}
	templatePath := strings.TrimPrefix(path.Join(templatesDir, templateFile), "/")
	if templatePath == "" {
		return "", fmt.Errorf("template path is required")
	}
	templateDir := strings.Trim(strings.TrimSpace(path.Dir(templatePath)), "/")
	if templateDir == "" || templateDir == "." {
		templateDir = strings.Trim(strings.TrimSpace(rootPath), "/")
	}
	if templateDir == "" {
		return "", fmt.Errorf("template dir is required")
	}

	sha := ""
	if ref.Owner != "" && ref.Repo != "" && ref.Branch != "" {
		if got, err := getGiteaBranchHeadSHA(s.cfg, ref.Owner, ref.Repo, ref.Branch); err == nil {
			sha = strings.TrimSpace(got)
		}
	}
	lockKey := strings.Join([]string{ref.Owner, ref.Repo, ref.Branch, templateDir, sha}, "|")
	var out string
	if err := withNetlabSyncLock(lockKey, func() error {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		defer func() {
			_ = tw.Close()
			_ = gz.Close()
		}()

		var walkDir func(repoDir string) error
		walkDir = func(repoDir string) error {
			entries, err := listGiteaDirectory(s.cfg, ref.Owner, ref.Repo, repoDir, ref.Branch)
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
					if err := walkDir(entryPath); err != nil {
						return err
					}
					continue
				case "file":
					// ok
				default:
					continue
				}
				data, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, entryPath, ref.Branch)
				if err != nil {
					return err
				}
				rel := strings.TrimPrefix(entryPath, templateDir)
				rel = strings.TrimPrefix(rel, "/")
				tarName := rel
				if entryPath == templatePath {
					tarName = "topology.yml"
				}
				tarName = path.Clean(strings.TrimPrefix(tarName, "/"))
				if tarName == "." || tarName == "" || strings.HasPrefix(tarName, "..") {
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
			}
			return nil
		}

		if err := walkDir(templateDir); err != nil {
			return err
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
	return out, nil
}

func resolveTemplateRepoForProject(cfg Config, pc *userContext, policy GovernancePolicy, source string, customRepo string) (templateRepoRef, error) {
	owner := pc.userScope.GiteaOwner
	repo := pc.userScope.GiteaRepo
	branch := strings.TrimSpace(pc.userScope.DefaultBranch)
	isAdmin := isAdminUser(cfg, pc.claims.Username)

	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "user":
		// default
	case "blueprints", "blueprint":
		ref := strings.TrimSpace(pc.userScope.Blueprint)
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
	case "external":
		if !isAdmin && !policy.AllowUserExternalTemplateRepos {
			return templateRepoRef{}, fmt.Errorf("external template repos are not enabled by governance policy")
		}
		repoID := strings.TrimSpace(customRepo)
		if repoID == "" {
			return templateRepoRef{}, fmt.Errorf("external repo id is required")
		}
		found := externalTemplateRepoByIDForContext(pc, repoID)
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
		if !isAdmin && !policy.AllowCustomTemplateRepos {
			return templateRepoRef{}, fmt.Errorf("custom template repos are not enabled by governance policy")
		}
		customOwner, customName, err := parseGiteaRepoRef(customRepo)
		if err != nil {
			return templateRepoRef{}, err
		}
		if !isAdmin && customOwner != pc.userScope.GiteaOwner && customOwner != "skyforge" {
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
