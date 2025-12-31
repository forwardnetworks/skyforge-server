CREATE TABLE sf_users (
  username text PRIMARY KEY,
  display_name text,
  email text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz
);

CREATE TABLE sf_projects (
  id text PRIMARY KEY,
  slug text NOT NULL UNIQUE,
  name text NOT NULL,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  blueprint text,
  default_branch text,
  terraform_state_key text,
  tofu_init_template_id integer,
  tofu_plan_template_id integer,
  tofu_apply_template_id integer,
  ansible_run_template_id integer,
  netlab_run_template_id integer,
  aws_account_id text,
  aws_role_name text,
  aws_region text,
  aws_auth_method text,
  artifacts_bucket text,
  eve_server text,
  netlab_server text,
  legacy_project_id integer NOT NULL,
  gitea_owner text NOT NULL,
  gitea_repo text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sf_projects_created_by_idx ON sf_projects(created_by);

CREATE TABLE sf_project_members (
  project_id text NOT NULL REFERENCES sf_projects(id) ON DELETE CASCADE,
  username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','editor','viewer')),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, username)
);

CREATE INDEX sf_project_members_user_idx ON sf_project_members(username);

CREATE TABLE sf_project_groups (
  project_id text NOT NULL REFERENCES sf_projects(id) ON DELETE CASCADE,
  group_name text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner','editor','viewer')),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, group_name)
);

CREATE INDEX sf_project_groups_project_idx ON sf_project_groups(project_id);

CREATE TABLE sf_aws_sso_tokens (
  username text PRIMARY KEY,
  start_url text NOT NULL,
  region text NOT NULL,
  client_id text,
  client_secret text,
  client_secret_expires_at timestamptz,
  access_token text,
  access_token_expires_at timestamptz,
  refresh_token text,
  refresh_token_expires_at timestamptz,
  last_authenticated_at_utc timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sf_project_aws_static_credentials (
  project_id text PRIMARY KEY REFERENCES sf_projects(id) ON DELETE CASCADE,
  access_key_id text NOT NULL,
  secret_access_key text NOT NULL,
  session_token text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sf_audit_log (
  id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  actor_username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  actor_is_admin boolean NOT NULL DEFAULT false,
  impersonated_username text,
  action text NOT NULL,
  project_id text REFERENCES sf_projects(id) ON DELETE SET NULL,
  details text
);

CREATE INDEX sf_audit_log_created_at_idx ON sf_audit_log(created_at DESC);
CREATE INDEX sf_audit_log_actor_idx ON sf_audit_log(actor_username);

CREATE TABLE sf_notifications (
  id uuid PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  title text NOT NULL,
  message text,
  type text NOT NULL,
  category text,
  reference_id text,
  priority text,
  is_read boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sf_notifications_user_idx ON sf_notifications(username, created_at DESC);

CREATE TABLE sf_settings (
  key text PRIMARY KEY,
  value text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
