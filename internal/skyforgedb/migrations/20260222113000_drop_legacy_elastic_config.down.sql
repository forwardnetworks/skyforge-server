-- Recreate legacy Elastic integration storage schema.
CREATE TABLE IF NOT EXISTS sf_user_elastic_config (
  username TEXT PRIMARY KEY,
  url TEXT NOT NULL DEFAULT '',
  auth_type TEXT NOT NULL DEFAULT 'none',
  api_key_enc BYTEA,
  basic_user TEXT NOT NULL DEFAULT '',
  basic_pass_enc BYTEA,
  index_prefix TEXT NOT NULL DEFAULT '',
  verify_tls BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sf_user_elastic_config_updated_at
  ON sf_user_elastic_config(updated_at);
