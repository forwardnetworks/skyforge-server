CREATE TABLE IF NOT EXISTS sf_user_aws_sso_credentials (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  start_url text NOT NULL,
  region text NOT NULL,
  account_id text NOT NULL,
  role_name text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

