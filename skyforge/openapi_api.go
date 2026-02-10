package skyforge

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openapiSpec []byte

// SwaggerOpenAPI serves the OpenAPI schema.
//
//encore:api public raw method=GET path=/swagger/openapi.json
func (s *Service) SwaggerOpenAPI(w http.ResponseWriter, req *http.Request) {
	if len(openapiSpec) == 0 {
		http.Error(w, "OpenAPI schema is empty", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiSpec)
}

// OpenAPI serves the OpenAPI schema (alias for tooling and docs UIs).
//
//encore:api public raw method=GET path=/openapi.json
func (s *Service) OpenAPI(w http.ResponseWriter, req *http.Request) {
	if len(openapiSpec) == 0 {
		http.Error(w, "OpenAPI schema is empty", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiSpec)
}
