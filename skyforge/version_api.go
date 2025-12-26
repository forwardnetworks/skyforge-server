package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
)

type VersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"buildTime,omitempty"`
}

// Version reports the running server version info.
//
//encore:api public method=GET path=/version
func (s *Service) Version(ctx context.Context) (*VersionResponse, error) {
	_ = ctx
	version := strings.TrimSpace(getenv("APP_VERSION", ""))
	buildTime := strings.TrimSpace(getenv("BUILD_TIME", ""))
	if version == "" && buildTime == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("version not set").Err()
	}
	return &VersionResponse{
		Version:   version,
		BuildTime: buildTime,
	}, nil
}

