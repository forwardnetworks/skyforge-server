package skyforge

import "encore.dev/beta/errs"

// authorizeSemaphoreProjectID ensures the authenticated user has access to the
// given Semaphore project ID.
//
// This is used for endpoints that are scoped by a Semaphore project ID rather than
// a Skyforge project key/slug (which should use projectContextForUser).
func (s *Service) authorizeSemaphoreProjectID(claims *SessionClaims, projectID int) error {
	if claims == nil {
		return errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	if projectID <= 0 {
		return errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}
	projects, err := s.projectStore.load()
	if err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to load projects").Err()
	}
	if p := findProjectBySemaphoreID(projects, projectID); p != nil {
		if projectAccessLevelForClaims(s.cfg, *p, claims) == "none" {
			return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
		}
		return nil
	}
	if !isAdminUser(s.cfg, claims.Username) && projectID != s.cfg.DefaultProject {
		return errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	return nil
}

