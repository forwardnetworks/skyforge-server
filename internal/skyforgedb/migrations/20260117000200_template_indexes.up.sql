CREATE TABLE IF NOT EXISTS sf_template_indexes (
  kind TEXT NOT NULL,
  owner TEXT NOT NULL,
  repo TEXT NOT NULL,
  branch TEXT NOT NULL,
  dir TEXT NOT NULL,
  head_sha TEXT NOT NULL,
  templates JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, owner, repo, branch, dir)
);

CREATE INDEX IF NOT EXISTS idx_sf_template_indexes_updated_at
  ON sf_template_indexes (updated_at DESC);

