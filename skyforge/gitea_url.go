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
