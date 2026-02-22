-- Recreate legacy single-collector credentials schema (empty) for rollback.
CREATE TABLE IF NOT EXISTS sf_user_forward_credentials (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  base_url text NOT NULL,
  skip_tls_verify boolean NOT NULL DEFAULT false,
  forward_username text NOT NULL,
  forward_password text NOT NULL,
  collector_id text,
  collector_username text,
  authorization_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
