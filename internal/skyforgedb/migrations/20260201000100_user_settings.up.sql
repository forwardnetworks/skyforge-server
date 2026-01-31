CREATE TABLE IF NOT EXISTS sf_user_settings (
  user_id TEXT PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  default_forward_collector_config_id TEXT NOT NULL DEFAULT '',
  default_env_json TEXT NOT NULL DEFAULT '[]',
  updated_at timestamptz NOT NULL DEFAULT now()
);
