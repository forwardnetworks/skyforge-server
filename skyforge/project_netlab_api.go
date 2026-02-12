package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type WorkspaceNetlabTemplatesResponse struct {
	WorkspaceID string   `json:"workspaceId"`
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Dir         string   `json:"dir"`
	Templates   []string `json:"templates"`
	HeadSHA     string   `json:"headSha,omitempty"`
	Cached      bool     `json:"cached"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
}

type WorkspaceNetlabTemplatesRequest struct {
	Dir    string `query:"dir" encore:"optional"`
	Source string `query:"source" encore:"optional"` // "workspace" (default), "blueprints", or "custom"
	Repo   string `query:"repo" encore:"optional"`   // owner/repo or URL (custom only)
}

type WorkspaceNetlabValidateRequest struct {
	Source      string  `json:"source,omitempty"` // workspace|blueprints|external|custom
	Repo        string  `json:"repo,omitempty"`   // owner/repo or URL (custom only)
	Dir         string  `json:"dir,omitempty"`    // repo-relative dir
	Template    string  `json:"template"`         // repo-relative file within Dir (may include subdirs)
	Environment JSONMap `json:"environment,omitempty"`
	// SetOverrides are netlab CLI `--set` overrides (highest precedence) applied during validation.
	// They are only used by the in-cluster netlab generator (netlab-c9s), not BYOS netlab.
	SetOverrides []string `json:"setOverrides,omitempty"`
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

	dir := "blueprints/netlab"
	if source == "blueprints" || source == "blueprint" || source == "external" {
		dir = "netlab"
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
	var cachedIdx *templateIndexRecord
	if cached, err := loadTemplateIndex(ctx, s.db, "netlab", owner, repo, branch, dir); err == nil && cached != nil {
		cachedIdx = cached
		if headSHA != "" && strings.TrimSpace(cached.HeadSHA) != "" && cached.HeadSHA == headSHA {
			sort.Strings(cached.Templates)
			return &WorkspaceNetlabTemplatesResponse{
				WorkspaceID: pc.workspace.ID,
				Repo:        fmt.Sprintf("%s/%s", owner, repo),
				Branch:      branch,
				Dir:         dir,
				Templates:   cached.Templates,
				HeadSHA:     cached.HeadSHA,
				Cached:      true,
				UpdatedAt:   cached.UpdatedAt.UTC().Format(time.RFC3339),
			}, nil
		}
		// If we can't resolve the branch head SHA (temporary Gitea error),
		// serve a reasonably fresh cached value to avoid re-scanning huge dirs.
		if headSHA == "" && time.Since(cached.UpdatedAt) < 10*time.Minute {
			sort.Strings(cached.Templates)
			return &WorkspaceNetlabTemplatesResponse{
				WorkspaceID: pc.workspace.ID,
				Repo:        fmt.Sprintf("%s/%s", owner, repo),
				Branch:      branch,
				Dir:         dir,
				Templates:   cached.Templates,
				HeadSHA:     cached.HeadSHA,
				Cached:      true,
				UpdatedAt:   cached.UpdatedAt.UTC().Format(time.RFC3339),
			}, nil
		}
	}

	var (
		templates []string
		listErr   error
	)
	// The directory-by-directory contents scan can be extremely slow on large template repos. Prefer a
	// single Gitea git-tree call when we have a resolved HEAD SHA.
	if headSHA != "" {
		templates, listErr = listNetlabTemplatesViaGitTree(s.cfg, owner, repo, headSHA, dir, 2000)
	}
	if listErr != nil || templates == nil {
		templates, listErr = listNetlabTemplatesRecursive(s.cfg, owner, repo, branch, dir, "", 4, false, 2000)
	}
	if listErr != nil {
		log.Printf("netlab templates list: %v", listErr)
		if cachedIdx != nil {
			sort.Strings(cachedIdx.Templates)
			return &WorkspaceNetlabTemplatesResponse{
				WorkspaceID: pc.workspace.ID,
				Repo:        fmt.Sprintf("%s/%s", owner, repo),
				Branch:      branch,
				Dir:         dir,
				Templates:   cachedIdx.Templates,
				HeadSHA:     cachedIdx.HeadSHA,
				Cached:      true,
				UpdatedAt:   cachedIdx.UpdatedAt.UTC().Format(time.RFC3339),
			}, nil
		}
		if strings.Contains(strings.ToLower(listErr.Error()), "too many templates") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("too many templates in this folder; choose a narrower dir").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query templates").Err()
	}
	sort.Strings(templates)

	if err := upsertTemplateIndex(ctx, s.db, "netlab", owner, repo, branch, dir, headSHA, templates); err != nil {
		log.Printf("template index upsert: %v", err)
	} else {
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}

	return &WorkspaceNetlabTemplatesResponse{
		WorkspaceID: pc.workspace.ID,
		Repo:        fmt.Sprintf("%s/%s", owner, repo),
		Branch:      branch,
		Dir:         dir,
		Templates:   templates,
		HeadSHA:     headSHA,
		Cached:      false,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ValidateWorkspaceNetlabTemplate runs `netlab create` against a selected template bundle without deploying it.
// This catches missing images, invalid attributes, and missing required plugins/templates.
//
//encore:api auth method=POST path=/api/workspaces/:id/netlab/validate
func (s *Service) ValidateWorkspaceNetlabTemplate(ctx context.Context, id string, req *WorkspaceNetlabValidateRequest) (*WorkspaceRunResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil || strings.TrimSpace(req.Template) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}

	source := "workspace"
	if v := strings.ToLower(strings.TrimSpace(req.Source)); v != "" {
		source = v
	}
	templateRepo := strings.TrimSpace(req.Repo)
	dir := strings.Trim(strings.TrimSpace(req.Dir), "/")
	if dir == "" {
		dir = "blueprints/netlab"
		if source == "blueprints" || source == "blueprint" || source == "external" {
			dir = "netlab"
		}
	}
	template := strings.TrimPrefix(strings.TrimSpace(req.Template), "/")

	envAny, _ := fromJSONMap(req.Environment)
	env := parseEnvMap(envAny)
	setOverrides := []string{}
	for _, raw := range req.SetOverrides {
		if v := strings.TrimSpace(raw); v != "" {
			setOverrides = append(setOverrides, v)
		}
	}

	meta, err := toJSONMap(map[string]any{
		"source":       source,
		"repo":         templateRepo,
		"dir":          dir,
		"template":     template,
		"environment":  env,
		"setOverrides": setOverrides,
		"dedupeKey": fmt.Sprintf(
			"netlab-validate:%s:%s:%s:%s:%s:%s",
			pc.workspace.ID,
			source,
			dir,
			template,
			strings.TrimSpace(env["NETLAB_DEVICE"]),
			strings.Join(setOverrides, ","),
		),
		"spec": map[string]any{
			"templateSource": source,
			"templateRepo":   templateRepo,
			"templatesDir":   dir,
			"template":       template,
			"environment":    env,
			"setOverrides":   setOverrides,
		},
	})
	if err != nil {
		log.Printf("netlab validate meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}

	task, err := createTask(ctx, s.db, pc.workspace.ID, nil, "netlab-validate", "Skyforge netlab validate", pc.claims.Username, meta)
	if err != nil {
		return nil, err
	}
	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("netlab validate task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}

type giteaTreeResponse struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"tree"`
}

func isNetlabTemplatePathExcluded(rel string) bool {
	// Exclude Netlab inventory/output folders that sometimes contain nested topology.yml files
	// but are not actually user-selectable templates.
	//
	// These commonly appear when a folder is synced from a runner workspace rather than a
	// clean example template checkout.
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	if rel == "" {
		return true
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		switch p {
		case "host_vars", "group_vars", "node_files", "check.config", "files":
			return true
		}
	}
	return false
}

func isNetlabTemplateYAMLFile(rel string) bool {
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	if rel == "" {
		return false
	}
	base := path.Base(rel)
	if !(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return false
	}

	// Helpers/shared defaults. These are not user-selectable templates.
	switch strings.ToLower(strings.TrimSpace(base)) {
	case "wait_times.yml", "wait_times.yaml",
		"warnings.yml", "warnings.yaml",
		"topology-defaults.yml", "topology-defaults.yaml",
		"ipv6-defaults.yml", "ipv6-defaults.yaml":
		return false
	}
	if strings.HasPrefix(strings.ToLower(base), "defaults-") {
		return false
	}
	if strings.HasSuffix(strings.ToLower(base), "-defaults.yml") || strings.HasSuffix(strings.ToLower(base), "-defaults.yaml") {
		return false
	}
	return true
}

func listNetlabTemplatesViaGitTree(cfg Config, owner, repo, headSHA, dir string, maxResults int) ([]string, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	headSHA = strings.TrimSpace(headSHA)
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	if owner == "" || repo == "" || headSHA == "" || dir == "" {
		return nil, fmt.Errorf("git tree template scan requires owner/repo/headSHA/dir")
	}

	// Use the Git API to fetch the full tree in one request and filter out template entrypoints.
	// This is dramatically faster than walking directory-by-directory via the contents API.
	apiPath := fmt.Sprintf(
		"/repos/%s/%s/git/trees/%s?recursive=1",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(headSHA),
	)
	resp, body, err := giteaDo(cfg, http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		fullURL := strings.TrimRight(cfg.Workspaces.GiteaAPIURL, "/") + apiPath
		return nil, fmt.Errorf("gitea %s responded %d: %s", fullURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed giteaTreeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}

	prefix := dir + "/"
	results := make([]string, 0, 128)
	for _, entry := range parsed.Tree {
		if entry.Type != "blob" {
			continue
		}
		p := strings.TrimPrefix(strings.TrimSpace(entry.Path), "/")
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rel := strings.TrimPrefix(p, prefix)
		if rel == "" {
			continue
		}
		if isNetlabTemplatePathExcluded(rel) {
			continue
		}

		if isNetlabTemplateYAMLFile(rel) {
			results = append(results, rel)
			if maxResults > 0 && len(results) >= maxResults {
				return nil, fmt.Errorf("too many templates")
			}
		}
	}
	return results, nil
}

func listNetlabTemplatesRecursive(cfg Config, owner, repo, branch, repoPath, relBase string, depth int, nested bool, maxResults int) ([]string, error) {
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
		if name == "host_vars" || name == "group_vars" || name == "node_files" || name == "check.config" || name == "files" {
			continue
		}
		entryPath := strings.TrimPrefix(strings.TrimSpace(entry.Path), "/")
		rel := path.Join(relBase, name)
		switch entry.Type {
		case "file":
			// We intentionally allow nested single-file templates (not just topology.yml entrypoints)
			// to support repos that store many templates in a single folder (for example module tests).
			if isNetlabTemplatePathExcluded(rel) {
				continue
			}
			if isNetlabTemplateYAMLFile(rel) {
				results = append(results, rel)
				if maxResults > 0 && len(results) >= maxResults {
					return nil, fmt.Errorf("too many templates")
				}
			}
		case "dir":
			if depth == 0 {
				continue
			}
			child, err := listNetlabTemplatesRecursive(cfg, owner, repo, branch, entryPath, rel, depth-1, true, maxResults)
			if err != nil {
				return nil, err
			}
			results = append(results, child...)
			if maxResults > 0 && len(results) >= maxResults {
				return nil, fmt.Errorf("too many templates")
			}
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
