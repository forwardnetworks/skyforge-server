package skyforge

import "strings"

func internalIntegrationURL(cfgValue string, fallback string) string {
	if v := strings.TrimSpace(cfgValue); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(strings.TrimSpace(fallback), "/")
}

func netboxInternalBaseURL(cfg Config) string {
	return internalIntegrationURL(cfg.NetboxInternalBaseURL, "http://netbox:8080/netbox")
}

func nautobotInternalBaseURL(cfg Config) string {
	return internalIntegrationURL(cfg.NautobotInternalBaseURL, "http://nautobot:8080")
}

func yaadeInternalBaseURL(cfg Config) string {
	return internalIntegrationURL(cfg.YaadeInternalBaseURL, "http://yaade")
}
