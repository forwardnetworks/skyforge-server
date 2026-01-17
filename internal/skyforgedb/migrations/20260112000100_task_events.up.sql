CREATE TABLE IF NOT EXISTS sf_task_events (
  id bigserial PRIMARY KEY,
  task_id bigint NOT NULL REFERENCES sf_tasks(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  event_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS sf_task_events_task_idx ON sf_task_events(task_id, id);
