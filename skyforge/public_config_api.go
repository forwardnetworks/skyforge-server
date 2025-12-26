package skyforge

import "context"

type PublicConfigResponse struct {
}

// PublicConfig exposes non-sensitive public UI configuration.
//
//encore:api public method=GET path=/api/public/config
func (s *Service) PublicConfig(_ context.Context) (*PublicConfigResponse, error) {
	return &PublicConfigResponse{}, nil
}
