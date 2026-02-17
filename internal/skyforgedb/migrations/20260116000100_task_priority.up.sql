ALTER TABLE sf_tasks
  ADD COLUMN IF NOT EXISTS priority integer NOT NULL DEFAULT 0;

-- Optimized queue scans for oldest/highest-priority tasks.
CREATE INDEX IF NOT EXISTS sf_tasks_queue_idx
  ON sf_tasks (owner_id, status, priority DESC, id);

CREATE INDEX IF NOT EXISTS sf_tasks_queue_deployment_idx
  ON sf_tasks (owner_id, deployment_id, status, priority DESC, id);
