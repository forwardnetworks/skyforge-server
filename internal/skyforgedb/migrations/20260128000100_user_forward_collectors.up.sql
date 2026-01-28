CREATE TABLE sf_user_forward_collectors (
  id text PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON DELETE CASCADE,
  name text NOT NULL,
  base_url text NOT NULL,
  skip_tls_verify boolean NOT NULL DEFAULT false,
  forward_username text NOT NULL,
  forward_password text NOT NULL,
  collector_id text,
  collector_username text,
  authorization_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  is_default boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX sf_user_forward_collectors_username_name
  ON sf_user_forward_collectors (username, name);

CREATE UNIQUE INDEX sf_user_forward_collectors_username_default
  ON sf_user_forward_collectors (username)
  WHERE is_default;

