CREATE TABLE IF NOT EXISTS sf_syslog_events (
  id bigserial PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now(),
  source_ip inet NOT NULL,
  hostname text,
  app_name text,
  proc_id text,
  msg_id text,
  facility integer,
  severity integer,
  message text,
  raw text NOT NULL
);

CREATE INDEX IF NOT EXISTS sf_syslog_events_received_at_idx ON sf_syslog_events(received_at DESC);
CREATE INDEX IF NOT EXISTS sf_syslog_events_source_ip_idx ON sf_syslog_events(source_ip);

CREATE TABLE IF NOT EXISTS sf_syslog_routes (
  source_cidr cidr PRIMARY KEY,
  owner_username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_syslog_routes_owner_idx ON sf_syslog_routes(owner_username);
