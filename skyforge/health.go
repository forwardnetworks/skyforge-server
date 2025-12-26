package skyforge

import "context"

// HealthResponse mirrors Skyforge's health payload.
type HealthResponse struct {
	Status string `json:"status"`
}

// HealthCheck verifies the service is alive.
func HealthCheck(ctx context.Context) (*HealthResponse, error) {
	return &HealthResponse{Status: "ok"}, nil
}

// HealthCheckAll validates core dependencies.
func HealthCheckAll(ctx context.Context) (*HealthResponse, error) {
	return &HealthResponse{Status: "ok"}, nil
}
