CREATE TABLE sf_project_azure_credentials (
  project_id text PRIMARY KEY REFERENCES sf_projects(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  client_id text NOT NULL,
  client_secret text NOT NULL,
  subscription_id text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sf_project_gcp_credentials (
  project_id text PRIMARY KEY REFERENCES sf_projects(id) ON DELETE CASCADE,
  service_account_json text NOT NULL,
  project_id_override text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
