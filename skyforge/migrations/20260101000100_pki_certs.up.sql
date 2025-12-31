CREATE TABLE sf_pki_certs (
  id text PRIMARY KEY,
  username text NOT NULL,
  project_id text REFERENCES sf_projects(id) ON DELETE SET NULL,
  common_name text NOT NULL,
  sans jsonb,
  cert_pem text NOT NULL,
  key_pem text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX sf_pki_certs_user_idx ON sf_pki_certs(username, issued_at DESC);
CREATE INDEX sf_pki_certs_project_idx ON sf_pki_certs(project_id);
