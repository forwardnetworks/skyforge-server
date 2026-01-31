CREATE TABLE IF NOT EXISTS sf_user_netlab_servers (
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

CREATE INDEX IF NOT EXISTS sf_user_netlab_servers_username_idx ON sf_user_netlab_servers(username);

CREATE TABLE IF NOT EXISTS sf_user_eve_servers (
  id uuid PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON DELETE CASCADE,
  name text NOT NULL,
  api_url text NOT NULL,
  web_url text,
  skip_tls_verify boolean NOT NULL DEFAULT false,
  api_user text,
  api_password text,
  ssh_host text,
  ssh_user text,
  ssh_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (username, name)
);

CREATE INDEX IF NOT EXISTS sf_user_eve_servers_username_idx ON sf_user_eve_servers(username);

