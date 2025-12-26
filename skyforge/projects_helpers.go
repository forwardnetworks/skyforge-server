package skyforge

import (
	"errors"
	"strings"

	"encore.dev/beta/errs"
)

var errProjectNotFound = errors.New("project not found")

func (s *Service) loadProjectByKey(projectKey string) ([]SkyforgeProject, int, SkyforgeProject, error) {
	projectKey = strings.TrimSpace(projectKey)
	if projectKey == "" {
		return nil, -1, SkyforgeProject{}, errors.New("project id is required")
	}
	projects, err := s.projectStore.load()
	if err != nil {
		return nil, -1, SkyforgeProject{}, err
	}
	for i, p := range projects {
		if p.ID == projectKey || p.Slug == projectKey {
			return projects, i, p, nil
		}
	}
	return projects, -1, SkyforgeProject{}, errProjectNotFound
}

type projectContext struct {
	projects []SkyforgeProject
	idx      int
	project  SkyforgeProject
	access   string
	claims   *SessionClaims
}

func (s *Service) projectContextForUser(user *AuthUser, projectKey string) (*projectContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	claims := claimsFromAuthUser(user)
	projects, idx, project, err := s.loadProjectByKey(projectKey)
	if err != nil {
		if errors.Is(err, errProjectNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("project not found").Err()
		}
		if err.Error() == "project id is required" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	access := projectAccessLevelForClaims(s.cfg, project, claims)
	if access == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return &projectContext{
		projects: projects,
		idx:      idx,
		project:  project,
		access:   access,
		claims:   claims,
	}, nil
}
