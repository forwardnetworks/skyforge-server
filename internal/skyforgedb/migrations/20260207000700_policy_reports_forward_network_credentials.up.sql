-- Store per-user Forward credentials ownerd to a Forward network id for Policy Reports.
-- Secrets are encrypted at rest by the application using the session secret key.

CREATE TABLE IF NOT EXISTS sf_policy_report_forward_network_credentials (
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  forward_network_id text NOT NULL,
  base_url_enc text NOT NULL,
  forward_username_enc text NOT NULL,
  forward_password_enc text NOT NULL,
  skip_tls_verify boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner_id, username, forward_network_id)
);

CREATE INDEX IF NOT EXISTS sf_pr_fwd_net_creds_ws_user_updated_idx
  ON sf_policy_report_forward_network_credentials(owner_id, username, updated_at DESC);

