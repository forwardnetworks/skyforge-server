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

type UserEveNgTemplatesResponse struct {
	OwnerUsername string   `json:"ownerUsername"`
	Repo          string   `json:"repo"`
	Branch        string   `json:"branch"`
	Dir           string   `json:"dir"`
	Templates     []string `json:"templates"`
}

type UserEveNgTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "user" (default), "blueprints", "external", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // repo id for external/custom sources
}

func (s *Service) listEveNgTemplatesForOwner(ctx context.Context, pc *ownerContext, req *UserEveNgTemplatesRequest) (*UserEveNgTemplatesResponse, error) {
	if pc == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user context required").Err()
	}

	source := canonicalTemplateSource("", "user")
	if req != nil {
		if v := strings.TrimSpace(req.Source); v != "" {
			source = canonicalTemplateSource(v, "user")
		}
	}

	owner := pc.context.GiteaOwner
	repo := pc.context.GiteaRepo
	branch := strings.TrimSpace(pc.context.DefaultBranch)
	policy, _ := loadGovernancePolicy(ctx, s.db)

	switch source {
	case "blueprints", "blueprint":
		ref := strings.TrimSpace(pc.context.Blueprint)
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
			return nil, errs.B().Code(errs.InvalidArgument).Msg("blueprints repo must be of form owner/repo").Err()
		}
		owner, repo = parts[0], parts[1]
		branch = ""
	case "external", "custom":
		if req == nil || strings.TrimSpace(req.Repo) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(source + " repo id is required").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, source, strings.TrimSpace(req.Repo))
		if err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "not enabled") {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
			}
			if strings.Contains(msg, "not allowed") {
				return nil, errs.B().Code(errs.PermissionDenied).Msg(err.Error()).Err()
			}
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		owner, repo, branch = ref.Owner, ref.Repo, ref.Branch
	case "user":
		// defaults already set
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown template source").Err()
	}

	if branch == "" {
		branch = "main"
		if b, err := getGiteaRepoDefaultBranch(s.cfg, owner, repo); err == nil && strings.TrimSpace(b) != "" {
			branch = strings.TrimSpace(b)
		}
	}

	dir := "blueprints/eve-ng"
	switch source {
	case "blueprints", "blueprint", "external", "custom":
		dir = "eve-ng"
	}
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
		log.Printf("eve-ng templates list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query templates").Err()
	}
	templates := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type != "dir" {
			continue
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		templates = append(templates, name)
	}
	sort.Strings(templates)

	return &UserEveNgTemplatesResponse{
		OwnerUsername: pc.context.ID,
		Repo:          fmt.Sprintf("%s/%s", owner, repo),
		Branch:        branch,
		Dir:           dir,
		Templates:     templates,
	}, nil
}

// GetEveNgTemplates lists EVE-NG templates for the authenticated user.
//
//encore:api auth method=GET path=/api/eve-ng/templates
func (s *Service) GetEveNgTemplates(ctx context.Context, req *UserEveNgTemplatesRequest) (*UserEveNgTemplatesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, personalOwnerRouteKey)
	if err != nil {
		return nil, err
	}
	return s.listEveNgTemplatesForOwner(ctx, pc, req)
}
