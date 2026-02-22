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

type WorkspaceTerraformTemplatesResponse struct {
	WorkspaceID string   `json:"userId"`
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Dir         string   `json:"dir"`
	Templates   []string `json:"templates"`
}

type WorkspaceTerraformTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "workspace" (default), "blueprints", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // owner/repo or URL (custom only)
}

// GetWorkspaceTerraformTemplates lists Terraform template directories for a workspace.
//
//encore:api auth method=GET path=/api/users/:id/terraform/templates
func (s *Service) GetWorkspaceTerraformTemplates(ctx context.Context, id string, req *WorkspaceTerraformTemplatesRequest) (*WorkspaceTerraformTemplatesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	policy, _ := loadGovernancePolicy(ctx, s.db)

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
		if req == nil || strings.TrimSpace(req.Repo) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("external repo id is required").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, "external", strings.TrimSpace(req.Repo))
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		owner, repo, branch = ref.Owner, ref.Repo, ref.Branch
	case "custom":
		if req == nil || strings.TrimSpace(req.Repo) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, "custom", strings.TrimSpace(req.Repo))
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

	switch source {
	case "blueprints", "blueprint", "external", "custom":
		// The shared blueprints repo has `terraform/` at the repo root.
		// A workspace repo syncs that same content under `blueprints/terraform/`.
		dir := "terraform"
		if req != nil {
			if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
				if !isSafeRelativePath(next) {
					return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
				}
				dir = next
			}
		}
		entries, err := listGiteaDirectory(s.cfg, owner, repo, dir, branch)
		if err != nil {
			log.Printf("terraform templates list: %v", err)
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
		return &WorkspaceTerraformTemplatesResponse{
			WorkspaceID: pc.workspace.ID,
			Repo:        fmt.Sprintf("%s/%s", owner, repo),
			Branch:      branch,
			Dir:         dir,
			Templates:   templates,
		}, nil
	default:
		dir := "blueprints/terraform"
		if req != nil {
			if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
				if !isSafeRelativePath(next) {
					return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
				}
				dir = next
			}
		}
		entries, err := listGiteaDirectory(s.cfg, owner, repo, dir, branch)
		if err != nil {
			log.Printf("terraform templates list: %v", err)
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
		return &WorkspaceTerraformTemplatesResponse{
			WorkspaceID: pc.workspace.ID,
			Repo:        fmt.Sprintf("%s/%s", owner, repo),
			Branch:      branch,
			Dir:         dir,
			Templates:   templates,
		}, nil
	}
	// unreachable
}
