package skyforge

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"path"
	"strings"
	"time"
)

type templateRepoRef struct {
	Owner  string
	Repo   string
	Branch string
}

func giteaDefaultBranch(cfg Config, owner, repo string) string {
	branch := "master"
	if b, err := getGiteaRepoDefaultBranch(cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
		branch = strings.TrimSpace(b)
	}
	return branch
}

func (s *Service) syncNetlabTopologyFile(ctx context.Context, pc *workspaceContext, server *NetlabServerConfig, templateSource, templateRepo, templatesDir, templateFile, workdir, owner string) error {
	if server == nil {
		return fmt.Errorf("netlab runner not configured")
	}
	templateFile = strings.TrimSpace(templateFile)
	if templateFile == "" {
		return nil
	}
	if templatesDir == "" {
		templatesDir = "blueprints/netlab"
	}
	templatesDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
	if strings.HasSuffix(templatesDir, ".yml") || strings.HasSuffix(templatesDir, ".yaml") {
		if templateFile == "" {
			templateFile = path.Base(templatesDir)
		}
		templatesDir = strings.Trim(strings.TrimSpace(path.Dir(templatesDir)), "/")
	}
	if !isSafeRelativePath(templatesDir) {
		return fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	ref, err := resolveTemplateRepoForProject(s.cfg, pc, templateSource, templateRepo)
	if err != nil {
		return err
	}

	sshCfg := NetlabConfig{
		SSHHost:    strings.TrimSpace(server.SSHHost),
		SSHUser:    strings.TrimSpace(server.SSHUser),
		SSHKeyFile: strings.TrimSpace(server.SSHKeyFile),
		StateRoot:  "/",
	}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return err
	}
	defer client.Close()

	destRoot := path.Join(workdir, "netlab")
	if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", destRoot), 10*time.Second); err != nil {
		return err
	}

	rootPath := strings.TrimPrefix(path.Join(templatesDir, path.Dir(templateFile)), "/")
	rootPath = strings.TrimSuffix(rootPath, "/")
	if rootPath == "" || rootPath == "." {
		rootPath = templatesDir
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

	if err := syncDir(rootPath); err != nil {
		return err
	}
	if owner != "" {
		_, _ = runSSHCommand(client, fmt.Sprintf("chown -R %q:%q %q >/dev/null 2>&1 || true", owner, owner, workdir), 8*time.Second)
	}
	return nil
}

func resolveTemplateRepoForProject(cfg Config, pc *workspaceContext, source string, customRepo string) (templateRepoRef, error) {
	owner := pc.workspace.GiteaOwner
	repo := pc.workspace.GiteaRepo
	branch := strings.TrimSpace(pc.workspace.DefaultBranch)

	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "workspace", "project":
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
	if templatesDir == "" {
		templatesDir = "blueprints/labpp"
	}
	templatesDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
	if !isSafeRelativePath(templatesDir) {
		return "", fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	if strings.TrimSpace(destRoot) == "" {
		destRoot = "/var/lib/skyforge/labpp-templates"
	}
	destRoot = strings.TrimRight(strings.TrimSpace(destRoot), "/")
	destTemplateDir := destRoot + "/" + templateName

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
		return "", fmt.Errorf("missing eve server sshHost (or apiUrl/webUrl)")
	}
	user := strings.TrimSpace(eveServer.SSHUser)
	if user == "" {
		user = strings.TrimSpace(s.cfg.Labs.EveSSHUser)
	}
	keyFile := strings.TrimSpace(s.cfg.Labs.EveSSHKeyFile)
	if keyFile == "" {
		return "", fmt.Errorf("missing SKYFORGE_EVE_SSH_KEY_FILE")
	}

	sshCfg := NetlabConfig{SSHHost: host, SSHUser: user, SSHKeyFile: keyFile, StateRoot: "/"}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return "", err
	}
	defer client.Close()

	rootPath := path.Join(templatesDir, templateName)
	if _, err := runSSHCommand(client, fmt.Sprintf("rm -rf %q && install -d -m 0755 %q", destTemplateDir, destTemplateDir), 15*time.Second); err != nil {
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
				if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", dest), 10*time.Second); err != nil {
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
				if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", path.Dir(dest)), 10*time.Second); err != nil {
					return err
				}
				if _, err := runSSHCommandWithInput(client, fmt.Sprintf("cat > %q", dest), body, 20*time.Second); err != nil {
					return err
				}
				_, _ = runSSHCommand(client, fmt.Sprintf("chmod 0644 %q >/dev/null 2>&1 || true", dest), 5*time.Second)
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
