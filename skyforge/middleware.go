package skyforge

import (
	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/middleware"
	"encore.dev/rlog"
)

// AdminMiddleware enforces admin access for endpoints tagged with admin.
//
//encore:middleware target=tag:admin
func (s *Service) AdminMiddleware(req middleware.Request, next middleware.Next) middleware.Response {
	userData := auth.Data()
	if userData == nil {
		return middleware.Response{
			Err: &errs.Error{
				Code:    errs.Unauthenticated,
				Message: "authentication required",
			},
		}
	}

	user, ok := userData.(*AuthUser)
	if !ok || user == nil {
		return middleware.Response{
			Err: &errs.Error{
				Code:    errs.Internal,
				Message: "invalid user data format",
			},
		}
	}

	if !user.IsAdmin && user.SelectedRole != "ADMIN" {
		rlog.Debug("admin access denied", "user", user.Username)
		return middleware.Response{
			Err: &errs.Error{
				Code:    errs.PermissionDenied,
				Message: "admin access required",
			},
		}
	}

	return next(req)
}

// UserListMiddleware enforces authentication for scope list endpoints.
//
// Deprecated middleware target removed with list-scopes route removal.
func (s *Service) UserListMiddleware(req middleware.Request, next middleware.Next) middleware.Response {
	if auth.Data() == nil {
		return middleware.Response{
			Err: &errs.Error{
				Code:    errs.Unauthenticated,
				Message: "authentication required",
			},
		}
	}
	return next(req)
}

// RunsListMiddleware enforces authentication for run list endpoints.
//
//encore:middleware target=tag:list-runs
func (s *Service) RunsListMiddleware(req middleware.Request, next middleware.Next) middleware.Response {
	if auth.Data() == nil {
		return middleware.Response{
			Err: &errs.Error{
				Code:    errs.Unauthenticated,
				Message: "authentication required",
			},
		}
	}
	return next(req)
}
