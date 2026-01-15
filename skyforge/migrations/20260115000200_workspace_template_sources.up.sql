ALTER TABLE sf_workspaces
  ADD COLUMN IF NOT EXISTS allow_external_template_repos boolean NOT NULL DEFAULT false;

ALTER TABLE sf_workspaces
  ADD COLUMN IF NOT EXISTS allow_custom_eve_servers boolean NOT NULL DEFAULT false;

ALTER TABLE sf_workspaces
  ADD COLUMN IF NOT EXISTS allow_custom_netlab_servers boolean NOT NULL DEFAULT false;

ALTER TABLE sf_workspaces
  ADD COLUMN IF NOT EXISTS external_template_repos jsonb NOT NULL DEFAULT '[]'::jsonb;
