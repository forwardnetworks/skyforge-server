package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

type UserScopeSettingsRequest struct {
	AllowExternalTemplateRepos     bool                   `json:"allowExternalTemplateRepos,omitempty"`
	AllowCustomEveServers          bool                   `json:"allowCustomEveServers,omitempty"`
	AllowCustomNetlabServers       bool                   `json:"allowCustomNetlabServers,omitempty"`
	AllowCustomContainerlabServers bool                   `json:"allowCustomContainerlabServers,omitempty"`
	ExternalTemplateRepos          []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
}

type UserScopeSettingsResponse struct {
	UserScope UserScope `json:"userScope"`
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
		if strings.Contains(ref, " ") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo").Err()
		}
		// Support:
		// - gitea-style owner/repo (default)
		// - full git URL (https://..., ssh://..., git@host:repo.git)
		if strings.Contains(ref, "://") || strings.HasPrefix(ref, "git@") {
			// Basic URL sanity.
			if strings.Contains(ref, "\n") || strings.Contains(ref, "\r") {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo").Err()
			}
		} else {
			parts := strings.Split(ref, "/")
			if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("external template repo must be of form owner/repo or a git URL").Err()
			}
			if !isValidUsername(parts[0]) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo owner").Err()
			}
			if !isSafeRelativePath(parts[1]) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo name").Err()
			}
			ref = strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
		}
		branch := strings.TrimSpace(repo.DefaultBranch)
		if strings.Contains(branch, " ") || strings.Contains(branch, "/..") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo branch").Err()
		}
		out = append(out, ExternalTemplateRepo{
			ID:            id,
			Name:          name,
			Repo:          ref,
			DefaultBranch: branch,
		})
	}
	return out, nil
}

// UpdateUserScopeSettings updates user-scope feature flags and template repo sources.
//
//encore:api auth method=PUT path=/api/users/:id/settings
func (s *Service) UpdateUserScopeSettings(ctx context.Context, id string, req *UserScopeSettingsRequest) (*UserScopeSettingsResponse, error) {
	pc, err := requireUserScopeOwner(ctx, s, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	userScopes, err := s.userScopeStore.load()
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user scopes").Err()
	}
	updated := false
	for i := range userScopes {
		if userScopes[i].ID != pc.userScope.ID {
			continue
		}
		validated, err := validateExternalTemplateRepos(req.ExternalTemplateRepos)
		if err != nil {
			return nil, err
		}
		userScopes[i].ExternalTemplateRepos = validated
		userScopes[i].AllowExternalTemplateRepos = req.AllowExternalTemplateRepos
		userScopes[i].AllowCustomEveServers = req.AllowCustomEveServers
		userScopes[i].AllowCustomNetlabServers = req.AllowCustomNetlabServers
		userScopes[i].AllowCustomContainerlabServers = req.AllowCustomContainerlabServers
		pc.userScope = userScopes[i]
		updated = true
		break
	}
	if !updated {
		return nil, errs.B().Code(errs.NotFound).Msg("user scope not found").Err()
	}
	if err := s.userScopeStore.upsert(pc.userScope); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save user-scope settings").Err()
	}
	if s.db != nil {
		_ = notifyUserScopesUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	return &UserScopeSettingsResponse{UserScope: pc.userScope}, nil
}
