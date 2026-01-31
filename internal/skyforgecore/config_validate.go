package skyforgecore

import (
	"fmt"
	"strings"
)

type ConfigValidation struct {
	Errors   []string
	Warnings []string
}

func (v *ConfigValidation) addError(format string, args ...any) {
	v.Errors = append(v.Errors, fmt.Sprintf(format, args...))
}

func (v *ConfigValidation) addWarning(format string, args ...any) {
	v.Warnings = append(v.Warnings, fmt.Sprintf(format, args...))
}

// ValidateConfig returns a safe-to-display validation summary of Skyforge runtime
// configuration.
//
// Notes:
//   - This function must never include secret values.
//   - It is safe to call from public endpoints (e.g. /status), but callers should
//     still avoid dumping the full list unless necessary.
func ValidateConfig(cfg Config) ConfigValidation {
	var v ConfigValidation

	netlabMode := strings.ToLower(strings.TrimSpace(cfg.NetlabC9sGeneratorMode))
	if netlabMode == "" {
		netlabMode = "k8s"
	}
	switch netlabMode {
	case "k8s":
		if strings.TrimSpace(cfg.NetlabGeneratorImage) == "" {
			v.addError("netlab generator image is not configured (NetlabGeneratorImage)")
		}
	case "remote":
		// BYOS netlab server mode; generator image is optional.
	default:
		v.addError("invalid netlab generator mode %q (expected 'k8s' or 'remote')", netlabMode)
	}

	if cfg.Features.DexEnabled && !cfg.UI.OIDCEnabled {
		v.addError("Dex is enabled but OIDC config is incomplete (login will not work)")
	}

	if cfg.Features.DNSEnabled && strings.TrimSpace(cfg.DNSURL) == "" {
		v.addError("DNS integration enabled but DNS URL is empty")
	}

	if cfg.Features.ForwardEnabled && strings.TrimSpace(cfg.ForwardCollectorImage) == "" {
		// Forward can still be used with external collectors; treat as warning.
		v.addWarning("Forward is enabled but in-cluster collector image is not configured")
	}

	if cfg.AIEnabled && cfg.GeminiEnabled {
		if strings.TrimSpace(cfg.GeminiProjectID) == "" {
			v.addWarning("Gemini is enabled but ProjectID is empty (user auth may still work, but Vertex calls will fail)")
		}
		if strings.TrimSpace(cfg.GeminiModel) == "" {
			v.addWarning("Gemini is enabled but Model is empty")
		}
	}

	return v
}
