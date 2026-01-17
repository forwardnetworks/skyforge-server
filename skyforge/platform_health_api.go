package skyforge

import (
	"encoding/json"
	"net/http"
)

// PlatformHealth serves the platform health payload.
//
//encore:api public raw method=GET path=/data/platform-health.json
func (s *Service) PlatformHealth(w http.ResponseWriter, req *http.Request) {
	summary, err := s.StatusSummary(req.Context())
	if err != nil {
		http.Error(w, "failed to load platform health data", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(summary.Checks)
}
