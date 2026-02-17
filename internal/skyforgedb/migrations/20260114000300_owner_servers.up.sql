CREATE TABLE IF NOT EXISTS sf_project_eve_servers (
  id uuid PRIMARY KEY,
  project_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  name text NOT NULL,
  api_url text NOT NULL,
  web_url text,
  skip_tls_verify boolean NOT NULL DEFAULT false,
  ssh_host text,
  ssh_user text,
  ssh_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS sf_project_eve_servers_project_idx ON sf_project_eve_servers(project_id);

CREATE TABLE IF NOT EXISTS sf_project_netlab_servers (
  id uuid PRIMARY KEY,
  project_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  name text NOT NULL,
  api_url text NOT NULL,
  api_insecure boolean NOT NULL DEFAULT true,
  api_token text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS sf_project_netlab_servers_project_idx ON sf_project_netlab_servers(project_id);
