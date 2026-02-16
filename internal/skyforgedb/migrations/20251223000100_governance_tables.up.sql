CREATE TABLE IF NOT EXISTS sf_resources (
  id uuid PRIMARY KEY,
  provider text NOT NULL,
  resource_id text NOT NULL,
  resource_type text NOT NULL,
  project_id text REFERENCES sf_projects(id) ON DELETE SET NULL,
  name text,
  region text,
  account_id text,
  owner_username text REFERENCES sf_users(username) ON UPDATE CASCADE,
  status text,
  tags jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_resources_provider_uq ON sf_resources(provider, resource_id);
CREATE INDEX IF NOT EXISTS sf_resources_project_idx ON sf_resources(project_id);
CREATE INDEX IF NOT EXISTS sf_resources_owner_idx ON sf_resources(owner_username);

CREATE TABLE IF NOT EXISTS sf_resource_events (
  id uuid PRIMARY KEY,
  resource_id uuid REFERENCES sf_resources(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  actor_username text REFERENCES sf_users(username) ON UPDATE CASCADE,
  actor_is_admin boolean NOT NULL DEFAULT false,
  impersonated_username text,
  project_id text REFERENCES sf_projects(id) ON DELETE SET NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_resource_events_resource_idx ON sf_resource_events(resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS sf_resource_events_project_idx ON sf_resource_events(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sf_cost_snapshots (
  id uuid PRIMARY KEY,
  resource_id uuid REFERENCES sf_resources(id) ON DELETE SET NULL,
  project_id text REFERENCES sf_projects(id) ON DELETE SET NULL,
  provider text NOT NULL,
  period_start date NOT NULL,
  period_end date NOT NULL,
  cost_amount numeric NOT NULL,
  cost_currency text NOT NULL DEFAULT 'USD',
  source text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_cost_snapshots_project_idx ON sf_cost_snapshots(project_id, period_end DESC);
CREATE INDEX IF NOT EXISTS sf_cost_snapshots_provider_idx ON sf_cost_snapshots(provider, period_end DESC);

CREATE TABLE IF NOT EXISTS sf_usage_snapshots (
  id uuid PRIMARY KEY,
  project_id text REFERENCES sf_projects(id) ON DELETE SET NULL,
  provider text NOT NULL,
  owner_type text NOT NULL,
  owner_id text,
  metric text NOT NULL,
  value numeric NOT NULL,
  unit text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  collected_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_usage_snapshots_project_idx ON sf_usage_snapshots(project_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS sf_usage_snapshots_provider_idx ON sf_usage_snapshots(provider, collected_at DESC);
