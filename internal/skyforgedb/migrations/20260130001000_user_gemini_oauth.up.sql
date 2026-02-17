CREATE TABLE IF NOT EXISTS sf_user_gemini_oauth (
  username TEXT PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  email TEXT NOT NULL,
  oauth_permissions TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sf_user_gemini_oauth_updated_at ON sf_user_gemini_oauth(updated_at);
