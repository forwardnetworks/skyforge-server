CREATE TABLE IF NOT EXISTS sf_user_aws_static_credentials (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  access_key_id text NOT NULL,
  secret_access_key text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sf_user_azure_credentials (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  client_id text NOT NULL,
  client_secret text NOT NULL,
  subscription_id text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sf_user_gcp_credentials (
  username text PRIMARY KEY REFERENCES sf_users(username) ON DELETE CASCADE,
  service_account_json text NOT NULL,
  project_id_override text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

