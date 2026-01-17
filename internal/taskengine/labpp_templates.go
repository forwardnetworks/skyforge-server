package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func defaultLabppTemplatesDir(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blueprints", "blueprint", "external":
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
	case "blueprints", "blueprint", "external":
		dir = strings.TrimPrefix(dir, "blueprints/")
	}
	return strings.Trim(strings.TrimSpace(dir), "/")
}

func (e *Engine) syncLabppTemplateDir(ctx context.Context, pc *workspaceContext, eveServer *EveServerConfig, templateSource, templateRepo, templatesDir, templateName, destRoot string) (string, error) {
	templateName = strings.TrimSpace(templateName)
	if templateName == "" {
		return "", fmt.Errorf("template is required")
	}
	templatesDir = normalizeLabppTemplatesDir(templateSource, templatesDir)
	if !isSafeRelativePath(templatesDir) {
		return "", fmt.Errorf("templatesDir must be a safe repo-relative path")
	}
	destRoot = strings.TrimRight(strings.TrimSpace(destRoot), "/")
	if destRoot == "" {
		return "", fmt.Errorf("destRoot is required")
	}
	destTemplateDir := filepath.Join(destRoot, templateName)

	ref, err := e.resolveTemplateRepoForWorkspace(pc, templateSource, templateRepo)
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
	if _, err := e.readGiteaFileBytes(ctx, ref.Owner, ref.Repo, labJSONPath, ref.Branch); err != nil {
		return "", fmt.Errorf("labpp template %q missing lab.json", templateName)
	}
	log.Printf("labpp template sync: repo=%s/%s branch=%s root=%s dest=%s", ref.Owner, ref.Repo, ref.Branch, rootPath, destTemplateDir)

	rootEntries, err := e.listGiteaDirectory(ref.Owner, ref.Repo, rootPath, ref.Branch)
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
		entries, err := e.listGiteaDirectory(ref.Owner, ref.Repo, repoPath, ref.Branch)
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
			if rel != "" && !isSafeRelativePath(rel) {
				return fmt.Errorf("unsafe template path %q", rel)
			}
			dest := filepath.Join(destTemplateDir, filepath.FromSlash(rel))
			switch entry.Type {
			case "dir":
				if err := os.MkdirAll(dest, 0o755); err != nil {
					return err
				}
				if err := syncDir(entryPath); err != nil {
					return err
				}
			case "file":
				body, err := e.readGiteaFileBytes(ctx, ref.Owner, ref.Repo, entryPath, ref.Branch)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
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
	return destRoot, nil
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
