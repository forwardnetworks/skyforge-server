CREATE TABLE IF NOT EXISTS sf_dns_tokens (
  username text PRIMARY KEY REFERENCES sf_users(username) ON UPDATE CASCADE,
  token text NOT NULL,
  zone text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
