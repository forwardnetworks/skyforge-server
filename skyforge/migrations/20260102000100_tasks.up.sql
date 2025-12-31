CREATE TABLE IF NOT EXISTS sf_tasks (
  id bigserial PRIMARY KEY,
  project_id text NOT NULL REFERENCES sf_projects(id) ON DELETE CASCADE,
  deployment_id uuid,
  task_type text NOT NULL,
  status text NOT NULL,
  message text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  error text
);

CREATE INDEX IF NOT EXISTS sf_tasks_project_idx ON sf_tasks(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS sf_tasks_deployment_idx ON sf_tasks(deployment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sf_task_logs (
  id bigserial PRIMARY KEY,
  task_id bigint NOT NULL REFERENCES sf_tasks(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  stream text NOT NULL DEFAULT 'stdout',
  output text NOT NULL
);

CREATE INDEX IF NOT EXISTS sf_task_logs_task_idx ON sf_task_logs(task_id, created_at);
