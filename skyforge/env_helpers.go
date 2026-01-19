package skyforge

import (
	"os"
	"strings"
)

// getenv returns the value of an environment variable or a fallback.
//
// Note: Skyforge is migrating most runtime configuration to typed Encore config,
// but a few build/runtime fields (e.g. version metadata) are still sourced from env.
func getenv(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
