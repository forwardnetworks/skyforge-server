CREATE TABLE IF NOT EXISTS sf_user_variable_groups (
  id serial PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  name text NOT NULL,
  variables jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_user_variable_groups_name_uq
  ON sf_user_variable_groups(username, name);

CREATE INDEX IF NOT EXISTS sf_user_variable_groups_username_idx
  ON sf_user_variable_groups(username, updated_at DESC);
