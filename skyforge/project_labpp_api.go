package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type WorkspaceLabppTemplatesResponse struct {
	WorkspaceID string   `json:"workspaceId"`
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Dir         string   `json:"dir"`
	Templates   []string `json:"templates"`
	HeadSHA     string   `json:"headSha,omitempty"`
	Cached      bool     `json:"cached"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
}

type WorkspaceLabppTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // workspace (default), blueprints, external, custom
	Repo   string `query:"repo" encore:"optional"`   // external repo id (external) or owner/repo url (custom)
}

// GetWorkspaceLabppTemplates lists LabPP templates for a workspace.
//
// Templates are expected to live under a repo directory (default: blueprints/labpp) where each
// template is a subdirectory (e.g. blueprints/labpp/junos-example/...).
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
	case "external":
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
		// default
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown template source").Err()
	}

	if branch == "" {
		branch = "main"
		if b, err := getGiteaRepoDefaultBranch(s.cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
			branch = strings.TrimSpace(b)
		}
	}

	dir := "blueprints/labpp"
	if source == "blueprints" || source == "blueprint" || source == "external" {
		dir = "labpp"
	}
	if req != nil {
		if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
			if !isSafeRelativePath(next) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
			}
			if source == "blueprints" || source == "blueprint" || source == "external" {
				next = strings.TrimPrefix(next, "blueprints/")
				next = strings.Trim(strings.TrimSpace(next), "/")
			}
			dir = next
		}
	}

	headSHA := ""
	{
		got, err := getGiteaBranchHeadSHA(s.cfg, owner, repo, branch)
		if err == nil {
			headSHA = strings.TrimSpace(got)
		}
	}
	if cached, err := loadTemplateIndex(ctx, s.db, "labpp", owner, repo, branch, dir); err == nil && cached != nil {
		if headSHA != "" && strings.TrimSpace(cached.HeadSHA) == headSHA {
			updatedAt := ""
			if !cached.UpdatedAt.IsZero() {
				updatedAt = cached.UpdatedAt.UTC().Format(time.RFC3339)
			}
			return &WorkspaceLabppTemplatesResponse{
				WorkspaceID: pc.workspace.ID,
				Repo:        fmt.Sprintf("%s/%s", owner, repo),
				Branch:      branch,
				Dir:         dir,
				Templates:   cached.Templates,
				HeadSHA:     cached.HeadSHA,
				Cached:      true,
				UpdatedAt:   updatedAt,
			}, nil
		}
	}

	entries, err := listGiteaDirectory(s.cfg, owner, repo, dir, branch)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list templates").Err()
	}
	templates := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type != "dir" {
			continue
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			continue
		}
		templates = append(templates, name)
	}
	sort.Strings(templates)
	_ = upsertTemplateIndex(ctx, s.db, "labpp", owner, repo, branch, dir, headSHA, templates)

	updatedAt := time.Now().UTC().Format(time.RFC3339)
	out := &WorkspaceLabppTemplatesResponse{
		WorkspaceID: pc.workspace.ID,
		Repo:        fmt.Sprintf("%s/%s", owner, repo),
		Branch:      branch,
		Dir:         dir,
		Templates:   templates,
		HeadSHA:     headSHA,
		Cached:      false,
		UpdatedAt:   updatedAt,
	}

	// Populate templates list even if empty, but verify that the directory exists and isn't a file.
	if len(entries) == 1 && strings.TrimSpace(entries[0].Type) == "file" {
		file := strings.TrimSpace(entries[0].Path)
		if file == "" {
			file = strings.TrimSpace(entries[0].Name)
		}
		return nil, errs.B().Code(errs.InvalidArgument).Msg(fmt.Sprintf("labpp template path is a file: %s", path.Clean(file))).Err()
	}

	raw, _ := json.Marshal(out)
	log.Printf("labpp templates: repo=%s/%s branch=%s dir=%s templates=%d payload=%dB", owner, repo, branch, dir, len(templates), len(raw))
	return out, nil
}
