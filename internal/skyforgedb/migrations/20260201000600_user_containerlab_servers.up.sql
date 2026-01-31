CREATE TABLE IF NOT EXISTS sf_user_containerlab_servers (
  id uuid PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON DELETE CASCADE,
  name text NOT NULL,
  api_url text NOT NULL,
  api_insecure boolean NOT NULL DEFAULT true,
  api_user text,
  api_password text,
  api_token text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (username, name)
);

CREATE INDEX IF NOT EXISTS sf_user_containerlab_servers_username_idx ON sf_user_containerlab_servers(username);

