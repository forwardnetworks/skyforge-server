CREATE TABLE IF NOT EXISTS sf_ldap_password_cache (
  username TEXT PRIMARY KEY,
  encrypted_password TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sf_ldap_password_cache_expires_at
  ON sf_ldap_password_cache (expires_at DESC);

