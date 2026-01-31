ALTER TABLE sf_workspaces
  ADD COLUMN IF NOT EXISTS allow_custom_containerlab_servers boolean NOT NULL DEFAULT false;

