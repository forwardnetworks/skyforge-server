ALTER TABLE sf_project_netlab_servers
  DROP COLUMN IF EXISTS api_user,
  DROP COLUMN IF EXISTS api_password;

ALTER TABLE sf_project_eve_servers
  DROP COLUMN IF EXISTS api_user,
  DROP COLUMN IF EXISTS api_password;

