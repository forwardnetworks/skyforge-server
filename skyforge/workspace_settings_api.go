package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

type WorkspaceSettingsRequest struct {
	AllowExternalTemplateRepos bool                   `json:"allowExternalTemplateRepos,omitempty"`
	AllowCustomNetlabServers   bool                   `json:"allowCustomNetlabServers,omitempty"`
	ExternalTemplateRepos      []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
}

type WorkspaceSettingsResponse struct {
	Workspace SkyforgeWorkspace `json:"workspace"`
}

func validateExternalTemplateRepos(repos []ExternalTemplateRepo) ([]ExternalTemplateRepo, error) {
	if len(repos) > 20 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("too many external template repos").Err()
	}
	seenIDs := map[string]bool{}
	out := make([]ExternalTemplateRepo, 0, len(repos))
	for _, repo := range repos {
		id := strings.TrimSpace(repo.ID)
		if id == "" {
			id = uuid.NewString()
		}
		if seenIDs[id] {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("duplicate external template repo id").Err()
		}
		seenIDs[id] = true

		name := strings.TrimSpace(repo.Name)
		if name == "" {
			name = id
		}
		ref := strings.Trim(strings.TrimSpace(repo.Repo), "/")
		if ref == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("external template repo is required").Err()
		}
		if strings.Contains(ref, "://") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("external template repo must be a gitea owner/repo").Err()
		}
		parts := strings.Split(ref, "/")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("external template repo must be of form owner/repo").Err()
		}
		if !isValidUsername(parts[0]) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo owner").Err()
		}
		if !isSafeRelativePath(parts[1]) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo name").Err()
		}
		branch := strings.TrimSpace(repo.DefaultBranch)
		if strings.Contains(branch, " ") || strings.Contains(branch, "/..") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo branch").Err()
		}
		out = append(out, ExternalTemplateRepo{
			ID:            id,
			Name:          name,
			Repo:          strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1]),
			DefaultBranch: branch,
		})
	}
	return out, nil
}

// UpdateWorkspaceSettings updates workspace-level feature flags and template repo sources.
//
//encore:api auth method=PUT path=/api/workspaces/:id/settings
func (s *Service) UpdateWorkspaceSettings(ctx context.Context, id string, req *WorkspaceSettingsRequest) (*WorkspaceSettingsResponse, error) {
	pc, err := requireWorkspaceOwner(ctx, s, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	updated := false
	for i := range workspaces {
		if workspaces[i].ID != pc.workspace.ID {
			continue
		}
		workspaces[i].AllowExternalTemplateRepos = req.AllowExternalTemplateRepos
		workspaces[i].AllowCustomNetlabServers = req.AllowCustomNetlabServers
		if req.AllowExternalTemplateRepos {
			validated, err := validateExternalTemplateRepos(req.ExternalTemplateRepos)
			if err != nil {
				return nil, err
			}
			workspaces[i].ExternalTemplateRepos = validated
		} else {
			workspaces[i].ExternalTemplateRepos = nil
		}
		pc.workspace = workspaces[i]
		updated = true
		break
	}
	if !updated {
		return nil, errs.B().Code(errs.NotFound).Msg("workspace not found").Err()
	}
	if err := s.workspaceStore.upsert(pc.workspace); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save workspace settings").Err()
	}
	if s.db != nil {
		_ = notifyWorkspacesUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	return &WorkspaceSettingsResponse{Workspace: pc.workspace}, nil
}
