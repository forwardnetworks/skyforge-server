CREATE TABLE sf_user_servicenow_configs (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  instance_url text NOT NULL,
  admin_username text NOT NULL,
  admin_password text NOT NULL,
  forward_base_url text NOT NULL,
  forward_username text NOT NULL,
  forward_password text NOT NULL,
  last_install_status text NOT NULL DEFAULT '',
  last_install_error text NOT NULL DEFAULT '',
  last_install_started_at timestamptz,
  last_install_finished_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

