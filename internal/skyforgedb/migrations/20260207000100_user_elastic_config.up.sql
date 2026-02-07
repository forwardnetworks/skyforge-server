CREATE TABLE IF NOT EXISTS sf_user_elastic_config (
  username TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  auth_type TEXT NOT NULL DEFAULT 'none', -- none | api_key | basic
  api_key_enc TEXT NOT NULL DEFAULT '',
  basic_username TEXT NOT NULL DEFAULT '',
  basic_password_enc TEXT NOT NULL DEFAULT '',
  index_prefix TEXT NOT NULL DEFAULT 'skyforge',
  verify_tls BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sf_user_elastic_config_updated_at ON sf_user_elastic_config(updated_at);

