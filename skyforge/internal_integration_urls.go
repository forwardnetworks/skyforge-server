package skyforge

import "strings"

func internalIntegrationURL(envKey, fallback string) string {
	raw := strings.TrimSpace(getenv(envKey, ""))
	if raw == "" {
		raw = strings.TrimSpace(fallback)
	}
	return strings.TrimRight(raw, "/")
}

func netboxInternalBaseURL(cfg Config) string {
	_ = cfg
	return internalIntegrationURL("SKYFORGE_NETBOX_INTERNAL_URL", "http://netbox:8080/netbox")
}

func nautobotInternalBaseURL(cfg Config) string {
	_ = cfg
	return internalIntegrationURL("SKYFORGE_NAUTOBOT_INTERNAL_URL", "http://nautobot:8080")
}

func yaadeInternalBaseURL(cfg Config) string {
	if strings.TrimSpace(cfg.YaadeBaseURL) != "" {
		return strings.TrimRight(cfg.YaadeBaseURL, "/")
	}
	return internalIntegrationURL("SKYFORGE_YAADE_INTERNAL_URL", "http://yaade")
}
