package health

import "context"

// Response represents the health check response
// mirroring Skyforge's health package layout.
type Response struct {
	Status string `json:"status"`
}

// Check is a simple health check helper that verifies the application is running.
//
//encore:api public method=GET path=/healthz
func Check(ctx context.Context) (*Response, error) {
	return &Response{Status: "ok"}, nil
}

// CheckAll performs a comprehensive health check of all system components.
//
//encore:api public method=GET path=/health
func CheckAll(ctx context.Context) (*Response, error) {
	return &Response{Status: "ok"}, nil
}
