package skyforge

import (
	"context"
	"log"
	"net/url"
	"path"
	"strings"

	"encore.dev/beta/errs"
)

type UserContextNetlabTemplateRequest struct {
	Dir      string `query:"dir" encore:"optional"`
	Source   string `query:"source" encore:"optional"`   // user (default), blueprints, external, custom
	Repo     string `query:"repo" encore:"optional"`     // external/custom selector (id or repo ref)
	Template string `query:"template" encore:"optional"` // repo-relative file within Dir (may include subdirs)
}

type UserContextNetlabTemplateResponse struct {
	UserContextID string `json:"userContextId"`
	Source        string `json:"source"`
	Repo          string `json:"repo,omitempty"`
	Branch        string `json:"branch,omitempty"`
	Dir           string `json:"dir"`
	Template      string `json:"template"`
	Path          string `json:"path"`
	YAML          string `json:"yaml"`
}

// GetUserContextNetlabTemplate reads a netlab YAML template from a user-context, blueprints, or external repo.
//
// This powers "View template" in the deployment creation flow.
//
//encore:api auth method=GET path=/api/user-contexts/:id/netlab/template
func (s *Service) GetUserContextNetlabTemplate(ctx context.Context, id string, req *UserContextNetlabTemplateRequest) (*UserContextNetlabTemplateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid request").Err()
	}

	source := strings.ToLower(strings.TrimSpace(req.Source))
	if source == "" {
		source = "user"
	}
	template := strings.TrimPrefix(strings.TrimSpace(req.Template), "/")
	if template == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}
	if !isSafeRelativePath(template) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a safe repo-relative path").Err()
	}

	owner := pc.userContext.GiteaOwner
	repo := pc.userContext.GiteaRepo
	branch := strings.TrimSpace(pc.userContext.DefaultBranch)
	policy, _ := loadGovernancePolicy(ctx, s.db)

	switch source {
	case "blueprints", "blueprint":
		ref := strings.TrimSpace(pc.userContext.Blueprint)
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
		if strings.TrimSpace(req.Repo) == "" {
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
		if strings.TrimSpace(req.Repo) == "" {
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
	case "user":
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

	dir := normalizeNetlabTemplatesDir(source, "")
	if next := strings.Trim(strings.TrimSpace(req.Dir), "/"); next != "" {
		if !isSafeRelativePath(next) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("dir must be a safe repo-relative path").Err()
		}
		dir = normalizeNetlabTemplatesDir(source, next)
	}
	filePath := path.Join(dir, template)

	var yamlText string
	if owner == "url" {
		if s.db == nil || s.box == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		creds, err := ensureUserGitDeployKey(ctx, s.db, s.box, pc.claims.Username)
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
		}
		body, err := readRepoFileBytes(ctx, creds, repo, branch, filePath)
		if err != nil {
			log.Printf("netlab template read: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to read netlab template").Err()
		}
		yamlText = string(body)
	} else {
		body, err := readGiteaFileBytes(s.cfg, owner, repo, filePath, branch)
		if err != nil {
			log.Printf("netlab template read: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to read netlab template").Err()
		}
		yamlText = string(body)
	}
	yamlText = strings.TrimRight(yamlText, "\n") + "\n"

	return &UserContextNetlabTemplateResponse{
		UserContextID: pc.userContext.ID,
		Source:        source,
		Repo: func() string {
			if source == "external" || source == "custom" {
				return strings.TrimSpace(req.Repo)
			}
			return ""
		}(),
		Branch:   branch,
		Dir:      dir,
		Template: template,
		Path:     filePath,
		YAML:     yamlText,
	}, nil
}
