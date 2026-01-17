package skyforgeconfig

import (
	"log"
	"os"
	"strings"

	secretreader "encore.app/internal/secrets"
)

// Encore-managed secrets fallback (matches encore.app).
// Encore populates this struct at runtime with configured secrets.
var secrets struct {
	SKYFORGE_SESSION_SECRET                      string
	SKYFORGE_OIDC_CLIENT_ID                      string
	SKYFORGE_OIDC_CLIENT_SECRET                  string
	SKYFORGE_LDAP_URL                            string
	SKYFORGE_LDAP_BIND_TEMPLATE                  string
	SKYFORGE_LDAP_LOOKUP_BINDDN                  string
	SKYFORGE_LDAP_LOOKUP_BINDPASSWORD            string
	SKYFORGE_DB_PASSWORD                         string
	SKYFORGE_GITEA_PASSWORD                      string
	SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY string
	SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY string
	SKYFORGE_INTERNAL_TOKEN                      string
	SKYFORGE_CONTAINERLAB_JWT_SECRET             string
	SKYFORGE_PKI_CA_CERT                         string
	SKYFORGE_PKI_CA_KEY                          string
	SKYFORGE_SSH_CA_KEY                          string
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
	case "SKYFORGE_GITEA_PASSWORD":
		return strings.TrimSpace(secrets.SKYFORGE_GITEA_PASSWORD)
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY":
		return strings.TrimSpace(secrets.SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY)
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY":
		return strings.TrimSpace(secrets.SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY)
	case "SKYFORGE_INTERNAL_TOKEN":
		return strings.TrimSpace(secrets.SKYFORGE_INTERNAL_TOKEN)
	case "SKYFORGE_CONTAINERLAB_JWT_SECRET":
		return strings.TrimSpace(secrets.SKYFORGE_CONTAINERLAB_JWT_SECRET)
	case "SKYFORGE_PKI_CA_CERT":
		return strings.TrimSpace(secrets.SKYFORGE_PKI_CA_CERT)
	case "SKYFORGE_PKI_CA_KEY":
		return strings.TrimSpace(secrets.SKYFORGE_PKI_CA_KEY)
	case "SKYFORGE_SSH_CA_KEY":
		return strings.TrimSpace(secrets.SKYFORGE_SSH_CA_KEY)
	default:
		return ""
	}
}

func secretFileNameForEnv(key string) string {
	switch key {
	case "SKYFORGE_ADMIN_PASSWORD":
		return "skyforge-admin-password"
	case "SKYFORGE_SESSION_SECRET":
		return "skyforge-session-secret"
	case "SKYFORGE_LDAP_URL":
		return "skyforge-ldap-url"
	case "SKYFORGE_LDAP_BIND_TEMPLATE":
		return "skyforge-ldap-bind-template"
	case "SKYFORGE_LDAP_LOOKUP_BINDDN":
		return "skyforge-ldap-lookup-binddn"
	case "SKYFORGE_LDAP_LOOKUP_BINDPASSWORD":
		return "skyforge-ldap-lookup-bindpassword"
	case "SKYFORGE_DB_PASSWORD":
		return "db-skyforge-server-password"
	case "SKYFORGE_GITEA_PASSWORD":
		return "gitea-admin-password"
	case "SKYFORGE_CONTAINERLAB_JWT_SECRET":
		return "skyforge-containerlab-jwt-secret"
	case "SKYFORGE_PKI_CA_CERT":
		return "skyforge-pki-ca-cert"
	case "SKYFORGE_PKI_CA_KEY":
		return "skyforge-pki-ca-key"
	case "SKYFORGE_SSH_CA_KEY":
		return "skyforge-ssh-ca-key"
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY":
		return "object-storage-terraform-access-key"
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY":
		return "object-storage-terraform-secret-key"
	case "SKYFORGE_INTERNAL_TOKEN":
		return "skyforge-internal-token"
	default:
		return ""
	}
}

func OptionalSecret(key string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	if fromFile := readSecretFromFileEnv(key + "_FILE"); fromFile != "" {
		return fromFile
	}
	secretName := secretFileNameForEnv(key)
	if secretName != "" {
		if fromFile, err := secretreader.ReadSecretFromEnvOrFile(key, secretName); err == nil && strings.TrimSpace(fromFile) != "" {
			_ = os.Setenv(key, fromFile)
			return strings.TrimSpace(fromFile)
		}
	}
	return strings.TrimSpace(getEncoreSecret(key))
}

func MustSecret(key string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	if fromFile := readSecretFromFileEnv(key + "_FILE"); fromFile != "" {
		_ = os.Setenv(key, fromFile)
		return fromFile
	}
	secretName := secretFileNameForEnv(key)
	if secretName != "" {
		if fromFile, err := secretreader.ReadSecretFromEnvOrFile(key, secretName); err == nil && strings.TrimSpace(fromFile) != "" {
			_ = os.Setenv(key, fromFile)
			return strings.TrimSpace(fromFile)
		}
	}
	if fromEncore := getEncoreSecret(key); strings.TrimSpace(fromEncore) != "" {
		return strings.TrimSpace(fromEncore)
	}
	log.Fatalf("missing required secret env var %s", key)
	return ""
}

func HydrateSecretEnv(keys ...string) {
	for _, key := range keys {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			continue
		}
		if val := strings.TrimSpace(OptionalSecret(key)); val != "" {
			_ = os.Setenv(key, val)
		}
	}
}

func readSecretFromFileEnv(key string) string {
	path := strings.TrimSpace(os.Getenv(key))
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
