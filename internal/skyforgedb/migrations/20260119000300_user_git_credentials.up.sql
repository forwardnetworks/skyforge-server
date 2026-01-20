CREATE TABLE IF NOT EXISTS sf_user_git_credentials (
  username text PRIMARY KEY,
  ssh_public_key text,
  ssh_private_key text,
  https_username text,
  https_token text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

