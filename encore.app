{
  "name": "Skyforge Server",
  "description": "Encore service for Skyforge",
  "services": [
    "skyforge",
    "worker",
    "health",
    "storage"
  ],
  "global_cors": {
    "allow_origins_with_credentials": [
      "http://localhost:3000",
      "http://localhost:4000",
      "http://localhost",
      "https://localhost:3000",
      "https://localhost:4000",
      "https://localhost"
    ],
    "allow_headers": [
      "Content-Type",
      "Accept",
      "x-current-role",
      "x-user-role",
      "x-user-id",
      "x-user-email"
    ],
    "expose_headers": [
      "Content-Length",
      "Content-Type",
      "x-user-role",
      "x-user-id",
      "x-user-email"
    ],
    "debug": false
  },
  "secrets": {
    "SKYFORGE_SESSION_SECRET": {},
    "SKYFORGE_ADMIN_PASSWORD": {},
    "SKYFORGE_OIDC_CLIENT_ID": {},
    "SKYFORGE_OIDC_CLIENT_SECRET": {},
    "SKYFORGE_LDAP_URL": {},
    "SKYFORGE_LDAP_BIND_TEMPLATE": {},
    "SKYFORGE_LDAP_LOOKUP_BINDDN": {},
    "SKYFORGE_LDAP_LOOKUP_BINDPASSWORD": {},
    "SKYFORGE_DB_PASSWORD": {},
    "SKYFORGE_GITEA_PASSWORD": {},
    "SKYFORGE_OBJECT_STORAGE_ROOT_USER": {},
    "SKYFORGE_OBJECT_STORAGE_ROOT_PASSWORD": {},
    "SKYFORGE_OBJECT_STORAGE_ACCESS_KEY": {},
    "SKYFORGE_OBJECT_STORAGE_SECRET_KEY": {},
    "SKYFORGE_INTERNAL_TOKEN": {},
    "SKYFORGE_CONTAINERLAB_JWT_SECRET": {},
    "SKYFORGE_PKI_CA_CERT": {},
    "SKYFORGE_PKI_CA_KEY": {},
    "SKYFORGE_SSH_CA_KEY": {},
    "YAADE_ADMIN_PASSWORD": {}
  }
}
