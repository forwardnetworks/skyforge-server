package skyforge

import (
	"net/http"
	"os"
	"path/filepath"
)

// PlatformHealth serves the platform health payload.
//
//encore:api public raw method=GET path=/data/platform-health.json
func (s *Service) PlatformHealth(w http.ResponseWriter, req *http.Request) {
	if s.cfg.PlatformDataDir == "" {
		http.Error(w, "platform health data not available", http.StatusNotFound)
		return
	}
	path := filepath.Join(s.cfg.PlatformDataDir, "platform-health.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "platform health data not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load platform health data", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
