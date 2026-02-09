-- User API tokens (PATs) for non-browser auth (MCP, scripts, etc).

CREATE TABLE IF NOT EXISTS sf_user_api_tokens (
  id uuid PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE ON DELETE CASCADE,
  name text NOT NULL DEFAULT '',
  token_prefix text NOT NULL,
  token_hash bytea NOT NULL,
  used_count bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_user_api_tokens_hash_uq
  ON sf_user_api_tokens(token_hash);

CREATE INDEX IF NOT EXISTS sf_user_api_tokens_user_created_idx
  ON sf_user_api_tokens(username, created_at DESC);

