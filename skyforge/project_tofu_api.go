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

type ProjectTofuTemplatesResponse struct {
	ProjectID string   `json:"projectId"`
	Repo      string   `json:"repo"`
	Branch    string   `json:"branch"`
	Dir       string   `json:"dir"`
	Templates []string `json:"templates"`
}

type ProjectTofuTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "project" (default), "blueprints", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // owner/repo or URL (custom only)
}

// GetProjectTofuTemplates lists Terraform template directories for a project.
//
//encore:api auth method=GET path=/api/workspaces/:id/tofu/templates
func (s *Service) GetProjectTofuTemplates(ctx context.Context, id string, req *ProjectTofuTemplatesRequest) (*ProjectTofuTemplatesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	source := "project"
	if req != nil {
		if v := strings.ToLower(strings.TrimSpace(req.Source)); v != "" {
			source = v
		}
	}

	owner := pc.project.GiteaOwner
	repo := pc.project.GiteaRepo
	branch := strings.TrimSpace(pc.project.DefaultBranch)

	switch source {
	case "blueprints", "blueprint":
		ref := strings.TrimSpace(pc.project.Blueprint)
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
		if !isAdminUser(s.cfg, pc.claims.Username) && customOwner != pc.project.GiteaOwner && customOwner != "skyforge" {
			return nil, errs.B().Code(errs.PermissionDenied).Msg("custom repo not allowed").Err()
		}
		owner, repo = customOwner, customRepo
		branch = ""
	case "project":
		// default already set
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown template source").Err()
	}

	if branch == "" {
		branch = "master"
		if b, err := getGiteaRepoDefaultBranch(s.cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
			branch = strings.TrimSpace(b)
		}
	}

	dir := "cloud/terraform/aws"
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
		log.Printf("tofu templates list: %v", err)
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
	return &ProjectTofuTemplatesResponse{
		ProjectID: pc.project.ID,
		Repo:      fmt.Sprintf("%s/%s", owner, repo),
		Branch:    branch,
		Dir:       dir,
		Templates: templates,
	}, nil
}
