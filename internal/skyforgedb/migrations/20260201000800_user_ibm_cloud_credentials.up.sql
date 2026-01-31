CREATE TABLE IF NOT EXISTS sf_user_ibm_cloud_credentials (
  username TEXT PRIMARY KEY,
  api_key TEXT NOT NULL,
  region TEXT NOT NULL,
  resource_group_id TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

