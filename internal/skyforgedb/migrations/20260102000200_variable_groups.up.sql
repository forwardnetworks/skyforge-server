CREATE TABLE IF NOT EXISTS sf_project_variable_groups (
  id bigserial PRIMARY KEY,
  project_id text NOT NULL REFERENCES sf_projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  variables jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_project_variable_groups_name_uq ON sf_project_variable_groups(project_id, name);
CREATE INDEX IF NOT EXISTS sf_project_variable_groups_project_idx ON sf_project_variable_groups(project_id, updated_at DESC);
