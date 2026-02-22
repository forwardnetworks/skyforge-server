-- Recreate legacy PKI/Gemini/AI tables as empty schema only.

CREATE TABLE IF NOT EXISTS sf_pki_certs (
  id text PRIMARY KEY,
  username text NOT NULL,
  workspace_id text REFERENCES sf_workspaces(id) ON DELETE SET NULL,
  common_name text NOT NULL,
  sans jsonb,
  cert_pem text NOT NULL,
  key_pem text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS sf_pki_certs_user_idx ON sf_pki_certs(username, issued_at DESC);
CREATE INDEX IF NOT EXISTS sf_pki_certs_workspace_idx ON sf_pki_certs(workspace_id);

CREATE TABLE IF NOT EXISTS sf_pki_ssh_certs (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  workspace_id TEXT NULL,
  principals JSONB NOT NULL,
  public_key TEXT NOT NULL,
  cert TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS sf_pki_ssh_certs_user_idx ON sf_pki_ssh_certs(username, issued_at DESC);
CREATE INDEX IF NOT EXISTS sf_pki_ssh_certs_workspace_idx ON sf_pki_ssh_certs(workspace_id);

CREATE TABLE IF NOT EXISTS sf_user_gemini_oauth (
  username TEXT PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  email TEXT NOT NULL,
  scopes TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sf_user_gemini_oauth_updated_at ON sf_user_gemini_oauth(updated_at);

CREATE TABLE IF NOT EXISTS sf_user_ai_generations (
  id uuid PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON DELETE CASCADE,
  provider text NOT NULL,
  kind text NOT NULL,
  prompt text NOT NULL,
  content text NOT NULL,
  warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sf_user_ai_generations_user_created ON sf_user_ai_generations(username, created_at DESC);
