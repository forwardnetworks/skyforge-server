package skyforge

import (
	"errors"
	"strings"

	"encore.dev/beta/errs"
)

var errWorkspaceNotFound = errors.New("workspace not found")

func (s *Service) loadWorkspaceByKey(workspaceKey string) ([]SkyforgeWorkspace, int, SkyforgeWorkspace, error) {
	workspaceKey = strings.TrimSpace(workspaceKey)
	if workspaceKey == "" {
		return nil, -1, SkyforgeWorkspace{}, errors.New("workspace id is required")
	}
	workspaces, err := s.workspaceStore.load()
	if err != nil {
		return nil, -1, SkyforgeWorkspace{}, err
	}
	for i, w := range workspaces {
		if w.ID == workspaceKey || w.Slug == workspaceKey {
			return workspaces, i, w, nil
		}
	}
	return workspaces, -1, SkyforgeWorkspace{}, errWorkspaceNotFound
}

type workspaceContext struct {
	workspaces []SkyforgeWorkspace
	idx        int
	workspace  SkyforgeWorkspace
	access     string
	claims     *SessionClaims
}

func (s *Service) workspaceContextForUser(user *AuthUser, workspaceKey string) (*workspaceContext, error) {
	if user == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	claims := claimsFromAuthUser(user)
	workspaces, idx, workspace, err := s.loadWorkspaceByKey(workspaceKey)
	if err != nil {
		if errors.Is(err, errWorkspaceNotFound) {
			return nil, errs.B().Code(errs.NotFound).Msg("workspace not found").Err()
		}
		if err.Error() == "workspace id is required" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load workspaces").Err()
	}
	access := workspaceAccessLevelForClaims(s.cfg, workspace, claims)
	if access == "none" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return &workspaceContext{
		workspaces: workspaces,
		idx:        idx,
		workspace:  workspace,
		access:     access,
		claims:     claims,
	}, nil
}
