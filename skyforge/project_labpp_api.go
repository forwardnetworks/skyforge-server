package skyforge

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"

	"encore.dev/beta/errs"
)

type WorkspaceLabppTemplatesResponse struct {
	WorkspaceID string   `json:"workspaceId"`
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Dir         string   `json:"dir"`
	Templates   []string `json:"templates"`
}

type WorkspaceLabppTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "workspace" (default), "blueprints", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // owner/repo or URL (custom only)
}

// GetWorkspaceLabppTemplates lists LabPP templates for a workspace.
//
// Templates are expected to live under a repo directory (default: blueprints/labpp)
// where each template is a subdirectory (e.g. blueprints/labpp/junos-example/...).
//
//encore:api auth method=GET path=/api/workspaces/:id/labpp/templates
func (s *Service) GetWorkspaceLabppTemplates(ctx context.Context, id string, req *WorkspaceLabppTemplatesRequest) (*WorkspaceLabppTemplatesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}

	source := "blueprints"
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
	case "external":
		if !pc.workspace.AllowExternalTemplateRepos {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("external template repos are disabled for this workspace").Err()
		}
		if req == nil || strings.TrimSpace(req.Repo) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("external repo id is required").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, "external", strings.TrimSpace(req.Repo))
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		owner, repo, branch = ref.Owner, ref.Repo, ref.Branch
	case "custom":
		if req == nil || strings.TrimSpace(req.Repo) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, "custom", strings.TrimSpace(req.Repo))
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "not enabled") {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
			}
			if strings.Contains(strings.ToLower(err.Error()), "not allowed") {
				return nil, errs.B().Code(errs.PermissionDenied).Msg(err.Error()).Err()
			}
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		owner, repo, branch = ref.Owner, ref.Repo, ref.Branch
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

	dir := defaultLabppTemplatesDir(source)
	if req != nil {
		if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
			if !isSafeRelativePath(next) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
			}
			dir = next
		}
	}
	dir = normalizeLabppTemplatesDir(source, dir)

	entries, err := listGiteaDirectory(s.cfg, owner, repo, dir, branch)
	if err != nil {
		log.Printf("labpp templates list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query templates").Err()
	}
	templates := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type != "dir" {
			continue
		}
		name := strings.TrimSpace(e.Name)
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		templates = append(templates, name)
	}
	sort.Strings(templates)
	_ = ctx
	return &WorkspaceLabppTemplatesResponse{
		WorkspaceID: pc.workspace.ID,
		Repo:        fmt.Sprintf("%s/%s", owner, repo),
		Branch:      branch,
		Dir:         dir,
		Templates:   templates,
	}, nil
}
