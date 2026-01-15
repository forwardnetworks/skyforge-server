package skyforge

import (
	"os"
	"strings"
)

// legacyEnvConfigEnabled reports whether the service should honor legacy, non-secret
// SKYFORGE_* environment variables as configuration overrides.
//
// Encore typed config (config.Load) is the preferred source of truth; when
// ENCORE_CFG_SKYFORGE is present, we disable legacy env overrides by default to
// avoid configuration drift between Helm/configmaps and typed config.
//
// Secrets (passwords/tokens/keys) are still read from env/secrets regardless.
func legacyEnvConfigEnabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SKYFORGE_FORCE_LEGACY_ENV_CONFIG")), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SKYFORGE_DISABLE_LEGACY_ENV_CONFIG")), "true") {
		return false
	}
	return strings.TrimSpace(os.Getenv("ENCORE_CFG_SKYFORGE")) == ""
}
