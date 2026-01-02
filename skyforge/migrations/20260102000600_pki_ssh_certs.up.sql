CREATE TABLE sf_pki_ssh_certs (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  project_id TEXT NULL,
  principals JSONB NOT NULL,
  public_key TEXT NOT NULL,
  cert TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX sf_pki_ssh_certs_user_idx ON sf_pki_ssh_certs(username, issued_at DESC);
CREATE INDEX sf_pki_ssh_certs_project_idx ON sf_pki_ssh_certs(project_id);
