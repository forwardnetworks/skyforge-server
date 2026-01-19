package skyforge

import (
	"strings"

	"encore.app/internal/skyforgecore"
	"encore.dev/middleware"
)

// ResponseHeadersMiddleware applies stable version headers to all non-raw API responses.
//
// Raw handlers must set headers themselves (they write directly to the network).
//
//encore:middleware target=all
func (s *Service) ResponseHeadersMiddleware(req middleware.Request, next middleware.Next) middleware.Response {
	resp := next(req)

	h := resp.Header()
	h.Set(skyforgecore.HeaderAPIVersion, skyforgecore.APIVersion)
	if build := strings.TrimSpace(getenv("APP_VERSION", "")); build != "" {
		h.Set(skyforgecore.HeaderBuild, build)
	}

	return resp
}
