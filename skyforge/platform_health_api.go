package skyforge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"encore.dev/beta/errs"
)

type RawJSONResponse struct {
	CacheControl string `header:"Cache-Control" json:"-"`
	ContentType  string `header:"Content-Type" json:"-"`
	data         json.RawMessage
}

func (r *RawJSONResponse) MarshalJSON() ([]byte, error) {
	return r.data, nil
}

// PlatformHealth serves the platform health payload.
//
//encore:api public method=GET path=/data/platform-health.json
func (s *Service) PlatformHealth(ctx context.Context) (*RawJSONResponse, error) {
	if s.cfg.PlatformDataDir == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("platform health data not available").Err()
	}
	path := filepath.Join(s.cfg.PlatformDataDir, "platform-health.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errs.B().Code(errs.NotFound).Msg("platform health data not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load platform health data").Err()
	}
	resp := &RawJSONResponse{
		CacheControl: "no-store",
		ContentType:  "application/json",
		data:         json.RawMessage(data),
	}
	return resp, nil
}
