package skyforge

import (
	"os"
	"strings"
)

// Encore-managed secrets fallback (matches encore.app).
var secrets struct {
	SKYFORGE_SESSION_SECRET                      string
	SKYFORGE_OIDC_CLIENT_ID                      string
	SKYFORGE_OIDC_CLIENT_SECRET                  string
	SKYFORGE_LDAP_URL                            string
	SKYFORGE_LDAP_BIND_TEMPLATE                  string
	SKYFORGE_LDAP_LOOKUP_BINDDN                  string
	SKYFORGE_LDAP_LOOKUP_BINDPASSWORD            string
	SKYFORGE_DB_PASSWORD                         string
	SKYFORGE_REDIS_PASSWORD                      string
	SKYFORGE_GITEA_PASSWORD                      string
	SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY string
	SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY string
	SKYFORGE_INTERNAL_TOKEN                      string
}

func getEncoreSecret(key string) string {
	switch key {
	case "SKYFORGE_SESSION_SECRET":
		return strings.TrimSpace(secrets.SKYFORGE_SESSION_SECRET)
	case "SKYFORGE_OIDC_CLIENT_ID":
		return strings.TrimSpace(secrets.SKYFORGE_OIDC_CLIENT_ID)
	case "SKYFORGE_OIDC_CLIENT_SECRET":
		return strings.TrimSpace(secrets.SKYFORGE_OIDC_CLIENT_SECRET)
	case "SKYFORGE_LDAP_URL":
		return strings.TrimSpace(secrets.SKYFORGE_LDAP_URL)
	case "SKYFORGE_LDAP_BIND_TEMPLATE":
		return strings.TrimSpace(secrets.SKYFORGE_LDAP_BIND_TEMPLATE)
	case "SKYFORGE_LDAP_LOOKUP_BINDDN":
		return strings.TrimSpace(secrets.SKYFORGE_LDAP_LOOKUP_BINDDN)
	case "SKYFORGE_LDAP_LOOKUP_BINDPASSWORD":
		return strings.TrimSpace(secrets.SKYFORGE_LDAP_LOOKUP_BINDPASSWORD)
	case "SKYFORGE_DB_PASSWORD":
		return strings.TrimSpace(secrets.SKYFORGE_DB_PASSWORD)
	case "SKYFORGE_REDIS_PASSWORD":
		return strings.TrimSpace(secrets.SKYFORGE_REDIS_PASSWORD)
	case "SKYFORGE_GITEA_PASSWORD":
		return strings.TrimSpace(secrets.SKYFORGE_GITEA_PASSWORD)
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY":
		return strings.TrimSpace(secrets.SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY)
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY":
		return strings.TrimSpace(secrets.SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY)
	case "SKYFORGE_INTERNAL_TOKEN":
		return strings.TrimSpace(secrets.SKYFORGE_INTERNAL_TOKEN)
	default:
		return ""
	}
}

func hydrateSecretEnv(keys ...string) {
	for _, key := range keys {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			continue
		}
		if val := strings.TrimSpace(getOptionalSecret(key)); val != "" {
			_ = os.Setenv(key, val)
		}
	}
}
