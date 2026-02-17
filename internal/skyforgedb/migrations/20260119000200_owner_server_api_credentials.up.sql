ALTER TABLE sf_project_netlab_servers
  ADD COLUMN IF NOT EXISTS api_user text,
  ADD COLUMN IF NOT EXISTS api_password text;

ALTER TABLE sf_project_eve_servers
  ADD COLUMN IF NOT EXISTS api_user text,
  ADD COLUMN IF NOT EXISTS api_password text;

