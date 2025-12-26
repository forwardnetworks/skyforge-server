CREATE TABLE IF NOT EXISTS sf_deployments (
  id uuid PRIMARY KEY,
  project_id text NOT NULL REFERENCES sf_projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  type text NOT NULL CHECK (type IN ('tofu','netlab')),
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_task_project_id integer,
  last_task_id integer,
  last_status text,
  last_started_at timestamptz,
  last_finished_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_deployments_project_name_uq ON sf_deployments(project_id, name);
CREATE INDEX IF NOT EXISTS sf_deployments_project_idx ON sf_deployments(project_id, updated_at DESC);
