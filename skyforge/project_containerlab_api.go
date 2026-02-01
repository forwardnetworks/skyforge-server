package skyforge

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type WorkspaceContainerlabTemplatesResponse struct {
	WorkspaceID string   `json:"workspaceId"`
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Dir         string   `json:"dir"`
	Templates   []string `json:"templates"`
}

type WorkspaceContainerlabTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "workspace" (default), "blueprints", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // owner/repo or URL (custom only)
}

// GetWorkspaceContainerlabTemplates lists Containerlab templates for a workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/containerlab/templates
func (s *Service) GetWorkspaceContainerlabTemplates(ctx context.Context, id string, req *WorkspaceContainerlabTemplatesRequest) (*WorkspaceContainerlabTemplatesResponse, error) {
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
		found := externalTemplateRepoByIDForContext(pc, strings.TrimSpace(req.Repo))
		if found == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown external repo").Err()
		}
		repoRef := strings.TrimSpace(found.Repo)
		if isGitURL(repoRef) {
			owner, repo = "url", repoRef
			branch = strings.TrimSpace(found.DefaultBranch)
		} else {
			ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, "external", strings.TrimSpace(req.Repo))
			if err != nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
			}
			owner, repo, branch = ref.Owner, ref.Repo, ref.Branch
		}
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
		if owner != "url" {
			if b, err := getGiteaRepoDefaultBranch(s.cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
				branch = strings.TrimSpace(b)
			}
		}
	}

	dir := normalizeContainerlabTemplatesDir(source, "")
	if req != nil {
		if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
			if !isSafeRelativePath(next) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
			}
			dir = normalizeContainerlabTemplatesDir(source, next)
		}
	}

	var templates []string
	if owner == "url" {
		if s.db == nil || s.box == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		creds, err := ensureUserGitDeployKey(ctx, s.db, s.box, pc.claims.Username)
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
		}
		headSHA := ""
		if cached, err := loadTemplateIndex(ctx, s.db, "containerlab-url", owner, repo, branch, dir); err == nil && cached != nil {
			headSHA = cached.HeadSHA
			// Serve cached templates for a short period to reduce clone churn.
			if time.Since(cached.UpdatedAt) < 10*time.Minute {
				templates = cached.Templates
			}
		}
		if templates == nil {
			head, listed, err := listRepoYAMLTemplates(ctx, creds, repo, branch, dir)
			if err != nil {
				log.Printf("containerlab external templates list: %v", err)
				return nil, errs.B().Code(errs.Unavailable).Msg("failed to query templates").Err()
			}
			headSHA = head
			templates = listed
			if err := upsertTemplateIndex(ctx, s.db, "containerlab-url", owner, repo, branch, dir, headSHA, templates); err != nil {
				log.Printf("template index upsert: %v", err)
			} else {
				_ = notifyDashboardUpdatePG(ctx, s.db)
			}
		}
	} else {
		entries, err := listGiteaDirectory(s.cfg, owner, repo, dir, branch)
		if err != nil {
			log.Printf("containerlab templates list: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to query templates").Err()
		}
		templates = make([]string, 0, len(entries))
		for _, e := range entries {
			if e.Type != "file" {
				continue
			}
			name := strings.TrimSpace(e.Name)
			if name == "" || strings.HasPrefix(name, ".") {
				continue
			}
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			templates = append(templates, name)
		}
	}
	sort.Strings(templates)
	_ = ctx
	return &WorkspaceContainerlabTemplatesResponse{
		WorkspaceID: pc.workspace.ID,
		Repo: func() string {
			if owner == "url" {
				return repo
			}
			return fmt.Sprintf("%s/%s", owner, repo)
		}(),
		Branch:    branch,
		Dir:       dir,
		Templates: templates,
	}, nil
}
