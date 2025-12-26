package skyforge

import (
	"context"
	"encoding/json"
	_ "embed"
)

//go:embed openapi.json
var openapiSpec []byte

// SwaggerOpenAPI serves the OpenAPI schema.
//
//encore:api public method=GET path=/swagger/openapi.json
func (s *Service) SwaggerOpenAPI(ctx context.Context) (*RawJSONResponse, error) {
	return &RawJSONResponse{
		CacheControl: "no-store",
		ContentType:  "application/json",
		data:         json.RawMessage(openapiSpec),
	}, nil
}
