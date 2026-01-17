CREATE TABLE IF NOT EXISTS sf_aws_device_auth_requests (
  request_id text PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  region text NOT NULL,
  start_url text NOT NULL,
  device_code text NOT NULL,
  user_code text NOT NULL,
  verification_uri_complete text NOT NULL,
  interval_seconds integer NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_aws_device_auth_requests_user_idx ON sf_aws_device_auth_requests(username, expires_at DESC);

CREATE TABLE IF NOT EXISTS sf_cloud_credential_status (
  key text PRIMARY KEY,
  ok boolean NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
