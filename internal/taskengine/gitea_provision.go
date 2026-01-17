package taskengine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"encore.app/integrations/gitea"
	"encore.app/internal/skyforgecore"
)

func giteaClientFor(cfg skyforgecore.Config, repoPrivate bool) *gitea.Client {
	return gitea.New(gitea.Config{
		APIURL:      strings.TrimRight(strings.TrimSpace(cfg.Workspaces.GiteaAPIURL), "/"),
		Username:    strings.TrimSpace(cfg.Workspaces.GiteaUsername),
		Password:    strings.TrimSpace(cfg.Workspaces.GiteaPassword),
		Timeout:     20 * time.Second,
		RepoPrivate: repoPrivate,
	})
}

func ensureGiteaRepo(cfg skyforgecore.Config, owner, repo string, repoPrivate bool) error {
	client := giteaClientFor(cfg, repoPrivate)
	if client == nil {
		return fmt.Errorf("gitea client unavailable")
	}
	if err := client.EnsureRepo(owner, repo); err != nil {
		return err
	}
	return client.SetRepoPrivate(owner, repo, repoPrivate)
}

func ensureGiteaFile(cfg skyforgecore.Config, owner, repo, filePath, content, message, branch string, author map[string]any) error {
	client := giteaClientFor(cfg, true)
	if client == nil {
		return fmt.Errorf("gitea client unavailable")
	}
	return client.EnsureFile(owner, repo, filePath, content, message, branch, author)
}

func giteaUserExists(cfg skyforgecore.Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	client := giteaClientFor(cfg, true)
	if client == nil {
		return false
	}
	resp, _, err := client.Do(http.MethodGet, fmt.Sprintf("/users/%s", url.PathEscape(username)), nil)
	return err == nil && resp.StatusCode == http.StatusOK
}

func ensureGiteaUserFromProfile(cfg skyforgecore.Config, username, displayName, email string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("missing username")
	}
	identity := gitea.Identity(displayName, username, email)
	derivedEmail, _ := identity["email"].(string)
	derivedName, _ := identity["name"].(string)
	if err := giteaClientFor(cfg, true).EnsureUser(username, derivedEmail, derivedName); err != nil {
		if strings.Contains(err.Error(), "e-mail already in use") {
			if giteaUserExists(cfg, username) {
				return nil
			}
			return fmt.Errorf("gitea email already in use for %s; resolve and retry", strings.TrimSpace(derivedEmail))
		}
		return err
	}
	return nil
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

func ensureBlueprintCatalogRepo(cfg skyforgecore.Config, blueprint string) error {
	owner, repo, ok := parseGiteaBlueprintSlug(blueprint)
	if !ok {
		return nil
	}
	// The shared blueprint catalog should always be visible to users in Gitea Explore.
	if err := ensureGiteaRepo(cfg, owner, repo, false); err != nil {
		return err
	}
	readme := "# Skyforge Blueprint Catalog\n\nThis repository contains validated deployment blueprints synced into user workspaces.\n"
	_ = ensureGiteaFile(cfg, owner, repo, "README.md", readme, "docs: add blueprint catalog README", "main", nil)

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
	return nil
}

func (e *Engine) syncGiteaDirectoryWithSourceToTarget(ctx context.Context, sourceOwner, sourceRepo, targetOwner, targetRepo, sourceDir, targetDir, sourceRef, targetBranch string) error {
	sourceDir = strings.TrimPrefix(strings.TrimSpace(sourceDir), "/")
	targetDir = strings.TrimPrefix(strings.TrimSpace(targetDir), "/")
	entries, err := e.listGiteaDirectory(sourceOwner, sourceRepo, sourceDir, sourceRef)
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
			if err := e.syncGiteaDirectoryWithSourceToTarget(ctx, sourceOwner, sourceRepo, targetOwner, targetRepo, entryPath, targetPath, sourceRef, targetBranch); err != nil {
				return err
			}
		case "file":
			body, err := e.readGiteaFileBytes(ctx, sourceOwner, sourceRepo, entryPath, sourceRef)
			if err != nil {
				return err
			}
			if err := ensureGiteaFile(e.cfg, targetOwner, targetRepo, targetPath, string(body), "sync: "+targetPath, targetBranch, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
