package skyforge

import "encore.app/internal/skyforgecore"

// secrets defines the Encore-managed secrets for the application.
var secrets struct {
	SKYFORGE_SESSION_SECRET             string `secret:"SKYFORGE_SESSION_SECRET"`
	SKYFORGE_ADMIN_PASSWORD             string `secret:"SKYFORGE_ADMIN_PASSWORD"`
	SKYFORGE_E2E_ADMIN_TOKEN            string `secret:"SKYFORGE_E2E_ADMIN_TOKEN"`
	SKYFORGE_OIDC_CLIENT_ID             string `secret:"SKYFORGE_OIDC_CLIENT_ID"`
	SKYFORGE_OIDC_CLIENT_SECRET         string `secret:"SKYFORGE_OIDC_CLIENT_SECRET"`
	SKYFORGE_GEMINI_OAUTH_CLIENT_SECRET string `secret:"SKYFORGE_GEMINI_OAUTH_CLIENT_SECRET"`
	SKYFORGE_LDAP_URL                   string `secret:"SKYFORGE_LDAP_URL"`
	SKYFORGE_LDAP_BIND_TEMPLATE         string `secret:"SKYFORGE_LDAP_BIND_TEMPLATE"`
	SKYFORGE_LDAP_LOOKUP_BINDDN         string `secret:"SKYFORGE_LDAP_LOOKUP_BINDDN"`
	SKYFORGE_LDAP_LOOKUP_BINDPASSWORD   string `secret:"SKYFORGE_LDAP_LOOKUP_BINDPASSWORD"`
	SKYFORGE_DB_PASSWORD                string `secret:"SKYFORGE_DB_PASSWORD"`
	SKYFORGE_GITEA_PASSWORD             string `secret:"SKYFORGE_GITEA_PASSWORD"`
	SKYFORGE_OBJECT_STORAGE_ACCESS_KEY  string `secret:"SKYFORGE_OBJECT_STORAGE_ACCESS_KEY"`
	SKYFORGE_OBJECT_STORAGE_SECRET_KEY  string `secret:"SKYFORGE_OBJECT_STORAGE_SECRET_KEY"`
	SKYFORGE_INTERNAL_TOKEN             string `secret:"SKYFORGE_INTERNAL_TOKEN"`
	SKYFORGE_CONTAINERLAB_JWT_SECRET    string `secret:"SKYFORGE_CONTAINERLAB_JWT_SECRET"`
	SKYFORGE_PKI_CA_CERT                string `secret:"SKYFORGE_PKI_CA_CERT"`
	SKYFORGE_PKI_CA_KEY                 string `secret:"SKYFORGE_PKI_CA_KEY"`
	SKYFORGE_SSH_CA_KEY                 string `secret:"SKYFORGE_SSH_CA_KEY"`
	YAADE_ADMIN_PASSWORD                string `secret:"YAADE_ADMIN_PASSWORD"`
}

func getSecrets() skyforgecore.Secrets {
	return skyforgecore.Secrets{
		SessionSecret:          secrets.SKYFORGE_SESSION_SECRET,
		AdminPassword:          secrets.SKYFORGE_ADMIN_PASSWORD,
		E2EAdminToken:          secrets.SKYFORGE_E2E_ADMIN_TOKEN,
		OIDCClientID:           secrets.SKYFORGE_OIDC_CLIENT_ID,
		OIDCClientSecret:       secrets.SKYFORGE_OIDC_CLIENT_SECRET,
		GeminiClientSecret:     secrets.SKYFORGE_GEMINI_OAUTH_CLIENT_SECRET,
		LDAPURL:                secrets.SKYFORGE_LDAP_URL,
		LDAPBindTemplate:       secrets.SKYFORGE_LDAP_BIND_TEMPLATE,
		LDAPLookupBindDN:       secrets.SKYFORGE_LDAP_LOOKUP_BINDDN,
		LDAPLookupBindPassword: secrets.SKYFORGE_LDAP_LOOKUP_BINDPASSWORD,
		DBPassword:             secrets.SKYFORGE_DB_PASSWORD,
		GiteaPassword:          secrets.SKYFORGE_GITEA_PASSWORD,
		ObjectStorageAccessKey: secrets.SKYFORGE_OBJECT_STORAGE_ACCESS_KEY,
		ObjectStorageSecretKey: secrets.SKYFORGE_OBJECT_STORAGE_SECRET_KEY,
		InternalToken:          secrets.SKYFORGE_INTERNAL_TOKEN,
		ContainerlabJWTSecret:  secrets.SKYFORGE_CONTAINERLAB_JWT_SECRET,
		PKICACert:              secrets.SKYFORGE_PKI_CA_CERT,
		PKICAKey:               secrets.SKYFORGE_PKI_CA_KEY,
		SSHCAKey:               secrets.SKYFORGE_SSH_CA_KEY,
		YaadeAdminPassword:     secrets.YAADE_ADMIN_PASSWORD,
	}
}
