CREATE TABLE sf_user_forward_credentials (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  base_url text NOT NULL,
  forward_username text NOT NULL,
  forward_password text NOT NULL,
  collector_id text,
  collector_username text,
  authorization_key text,
  device_username text,
  device_password text,
  jump_host text,
  jump_username text,
  jump_private_key text,
  jump_cert text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
