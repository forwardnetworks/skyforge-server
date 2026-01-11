package skyforge

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"path"
	"sort"
	"strings"

	"encore.dev/beta/errs"
)

type WorkspaceNetlabTemplatesResponse struct {
	WorkspaceID string   `json:"workspaceId"`
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Dir         string   `json:"dir"`
	Templates   []string `json:"templates"`
}

type WorkspaceNetlabTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "workspace" (default), "blueprints", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // owner/repo or URL (custom only)
}

// GetWorkspaceNetlabTemplates lists Netlab templates for a workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/netlab/templates
func (s *Service) GetWorkspaceNetlabTemplates(ctx context.Context, id string, req *WorkspaceNetlabTemplatesRequest) (*WorkspaceNetlabTemplatesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	source := "workspace"
	if req != nil {
		if v := strings.ToLower(strings.TrimSpace(req.Source)); v != "" {
			source = v
		}
	}

	owner := pc.workspace.GiteaOwner
	repo := pc.workspace.GiteaRepo
	branch := strings.TrimSpace(pc.workspace.DefaultBranch)

	switch source {
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
		if len(parts) >= 2 {
			owner, repo = parts[0], parts[1]
		} else {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("blueprints repo must be of form owner/repo").Err()
		}
		branch = ""
	case "custom":
		if req == nil || strings.TrimSpace(req.Repo) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		customOwner, customRepo, err := parseGiteaRepoRef(req.Repo)
		if err != nil {
			return nil, err
		}
		if !isAdminUser(s.cfg, pc.claims.Username) && customOwner != pc.workspace.GiteaOwner && customOwner != "skyforge" {
			return nil, errs.B().Code(errs.PermissionDenied).Msg("custom repo not allowed").Err()
		}
		owner, repo = customOwner, customRepo
		branch = ""
	case "workspace":
		// default already set
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown template source").Err()
	}

	if branch == "" {
		branch = "main"
		if b, err := getGiteaRepoDefaultBranch(s.cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
			branch = strings.TrimSpace(b)
		}
	}

	dir := "blueprints/netlab"
	if source == "blueprints" || source == "blueprint" {
		dir = "netlab"
	}
	if req != nil {
		if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
			if !isSafeRelativePath(next) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
			}
			if source == "blueprints" || source == "blueprint" {
				next = strings.TrimPrefix(next, "blueprints/")
				next = strings.Trim(strings.TrimSpace(next), "/")
			}
			dir = next
		}
	}

	templates, err := listNetlabTemplatesRecursive(s.cfg, owner, repo, branch, dir, "", 4, false)
	if err != nil {
		log.Printf("netlab templates list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query templates").Err()
	}
	sort.Strings(templates)
	_ = ctx
	return &WorkspaceNetlabTemplatesResponse{
		WorkspaceID: pc.workspace.ID,
		Repo:        fmt.Sprintf("%s/%s", owner, repo),
		Branch:      branch,
		Dir:         dir,
		Templates:   templates,
	}, nil
}

func listNetlabTemplatesRecursive(cfg Config, owner, repo, branch, repoPath, relBase string, depth int, nested bool) ([]string, error) {
	if depth < 0 {
		return nil, nil
	}
	entries, err := listGiteaDirectory(cfg, owner, repo, repoPath, branch)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		entryPath := strings.TrimPrefix(strings.TrimSpace(entry.Path), "/")
		rel := path.Join(relBase, name)
		switch entry.Type {
		case "file":
			if nested {
				if name == "topology.yml" || name == "topology.yaml" {
					results = append(results, rel)
				}
				continue
			}
			if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
				results = append(results, rel)
			}
		case "dir":
			if depth == 0 {
				continue
			}
			child, err := listNetlabTemplatesRecursive(cfg, owner, repo, branch, entryPath, rel, depth-1, true)
			if err != nil {
				return nil, err
			}
			results = append(results, child...)
		}
	}
	return results, nil
}

func parseGiteaRepoRef(input string) (string, string, error) {
	ref := strings.TrimSpace(input)
	if ref == "" {
		return "", "", errs.B().Code(errs.InvalidArgument).Msg("repo is required").Err()
	}
	if strings.Contains(ref, "://") {
		u, err := url.Parse(ref)
		if err != nil {
			return "", "", errs.B().Code(errs.InvalidArgument).Msg("invalid repo url").Err()
		}
		ref = strings.Trim(strings.TrimPrefix(u.Path, "/"), "/")
	}
	parts := strings.Split(strings.Trim(ref, "/"), "/")
	if len(parts) < 2 {
		return "", "", errs.B().Code(errs.InvalidArgument).Msg("repo must be of form owner/repo").Err()
	}
	return parts[0], parts[1], nil
}
