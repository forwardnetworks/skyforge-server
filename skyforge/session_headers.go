package skyforge

import (
	"net/http"
	"strings"
)

func addSessionHeaders(headers http.Header, claims *SessionClaims) {
	if headers == nil || claims == nil {
		return
	}
	headers.Set("X-Skyforge-Username", claims.Username)
	headers.Set("X-Skyforge-DisplayName", claims.DisplayName)
	headers.Set("Remote-User", claims.Username)
	headers.Set("X-Forwarded-User", claims.Username)
	// Provide a stable group header for downstream apps that support RemoteUser group sync.
	// LDAP group DNs often contain commas, so we avoid serializing the full group list here.
	headers.Set("Remote-User-Group", "skyforge-users")
	if strings.TrimSpace(claims.ActorUsername) != "" {
		headers.Set("X-Skyforge-Actor", strings.TrimSpace(claims.ActorUsername))
		headers.Set("X-Skyforge-Impersonating", boolString(isImpersonating(claims)))
	}
	if claims.Email != "" {
		headers.Set("X-Skyforge-Email", claims.Email)
		headers.Set("Remote-User-Email", claims.Email)
		headers.Set("X-Forwarded-Email", claims.Email)
	}
	if len(claims.Groups) > 0 {
		headers.Set("X-Skyforge-Groups", strings.Join(claims.Groups, ","))
	}

	firstName := ""
	lastName := ""
	if parts := strings.Fields(strings.TrimSpace(claims.DisplayName)); len(parts) > 0 {
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = strings.Join(parts[1:], " ")
		}
	}
	if firstName != "" {
		headers.Set("X-Skyforge-First-Name", firstName)
		headers.Set("Remote-User-First-Name", firstName)
		headers.Set("X-Forwarded-First-Name", firstName)
	}
	if lastName != "" {
		headers.Set("X-Skyforge-Last-Name", lastName)
		headers.Set("Remote-User-Last-Name", lastName)
		headers.Set("X-Forwarded-Last-Name", lastName)
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
