package skyforge

import "strings"

func internalIntegrationURL(cfgValue string, envKey, fallback string) string {
	if v := strings.TrimSpace(cfgValue); v != "" {
		return strings.TrimRight(v, "/")
	}
	if legacyEnvConfigEnabled() {
		if v := strings.TrimSpace(getenv(envKey, "")); v != "" {
			return strings.TrimRight(v, "/")
		}
	}
	return strings.TrimRight(strings.TrimSpace(fallback), "/")
}

func netboxInternalBaseURL(cfg Config) string {
	return internalIntegrationURL(cfg.NetboxInternalBaseURL, "SKYFORGE_NETBOX_INTERNAL_URL", "http://netbox:8080/netbox")
}

func nautobotInternalBaseURL(cfg Config) string {
	return internalIntegrationURL(cfg.NautobotInternalBaseURL, "SKYFORGE_NAUTOBOT_INTERNAL_URL", "http://nautobot:8080")
}

func yaadeInternalBaseURL(cfg Config) string {
	return internalIntegrationURL(cfg.YaadeInternalBaseURL, "SKYFORGE_YAADE_INTERNAL_URL", "http://yaade")
}
