package skyforge

import (
	"fmt"
	"net/url"
	"strings"
)

func withBasicAuthURL(rawURL, username, password string) string {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" || password == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.User = url.UserPassword(username, password)
	return parsed.String()
}

func giteaRawFileURL(cfg Config, owner, repo, branch, filePath string) string {
	base := normalizeGiteaBaseURL(ssoBaseURLOrDefault(cfg.GiteaBaseURL, ""))
	trimmed := strings.TrimPrefix(strings.TrimPrefix(filePath, "/"), "./")
	return fmt.Sprintf("%s/%s/%s/raw/branch/%s/%s", base, owner, repo, branch, trimmed)
}

func giteaInternalBaseURL(cfg Config) string {
	apiURL := strings.TrimRight(strings.TrimSpace(cfg.Workspaces.GiteaAPIURL), "/")
	base := ""
	if apiURL != "" {
		lower := strings.ToLower(apiURL)
		if strings.HasSuffix(lower, "/api/v1") {
			base = strings.TrimSuffix(apiURL, "/api/v1")
		} else {
			base = apiURL
		}
	}
	if base == "" {
		base = cfg.GiteaBaseURL
	}
	return normalizeGiteaBaseURL(base)
}
