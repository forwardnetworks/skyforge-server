ALTER TABLE sf_user_forward_credentials
  ADD COLUMN IF NOT EXISTS skip_tls_verify boolean NOT NULL DEFAULT false;
