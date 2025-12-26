ALTER TABLE sf_projects
  ADD COLUMN IF NOT EXISTS is_public boolean NOT NULL DEFAULT false;
