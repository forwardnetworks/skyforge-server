package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"encore.dev/beta/errs"
	"encore.dev/middleware"
)

// ErrorNormalizationMiddleware ensures that all API errors are returned as Encore errs,
// Use typed `errs.*` codes consistently.
//
//encore:middleware target=all
func (s *Service) ErrorNormalizationMiddleware(req middleware.Request, next middleware.Next) middleware.Response {
	resp := next(req)

	if resp.Err == nil {
		return resp
	}

	var e *errs.Error
	if errors.As(resp.Err, &e) {
		return resp
	}

	err := resp.Err

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		resp.Err = errs.B().Code(errs.DeadlineExceeded).Msg("deadline exceeded").Err()
	case errors.Is(err, context.Canceled):
		resp.Err = errs.B().Code(errs.Canceled).Msg("request canceled").Err()
	case errors.Is(err, sql.ErrNoRows):
		resp.Err = errs.B().Code(errs.NotFound).Msg("not found").Err()
	default:
		// Heuristic: try to avoid leaking details while still surfacing a useful high-level message.
		msg := strings.TrimSpace(err.Error())
		if msg == "" {
			msg = "internal error"
		}
		resp.Err = errs.B().Code(errs.Internal).Msg(msg).Err()
	}

	return resp
}
