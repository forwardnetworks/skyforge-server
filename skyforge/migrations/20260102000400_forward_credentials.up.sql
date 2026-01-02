CREATE TABLE sf_project_forward_credentials (
  project_id text PRIMARY KEY REFERENCES sf_projects(id) ON DELETE CASCADE,
  base_url text NOT NULL,
  username text NOT NULL,
  password text NOT NULL,
  device_username text,
  device_password text,
  jump_host text,
  jump_username text,
  jump_private_key text,
  jump_cert text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
