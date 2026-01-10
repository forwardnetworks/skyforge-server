package skyforge

import (
	"regexp"
	"strings"
)

var csrfFieldPattern = regexp.MustCompile(`name=["']_csrf["']\s+value=["']([^"']+)["']`)

func normalizeGiteaBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return strings.TrimRight(raw, "/")
}

func ssoBaseURLOrDefault(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return strings.TrimSpace(fallback)
	}
	return raw
}

func extractFormValue(body string, field string) string {
	if field != "_csrf" || body == "" {
		return ""
	}
	match := csrfFieldPattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}
