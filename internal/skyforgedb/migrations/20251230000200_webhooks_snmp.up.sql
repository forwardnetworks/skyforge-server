CREATE TABLE IF NOT EXISTS sf_webhook_tokens (
  username text PRIMARY KEY REFERENCES sf_users(username) ON UPDATE CASCADE,
  token text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sf_webhook_events (
  id bigserial PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now(),
  username text REFERENCES sf_users(username) ON UPDATE CASCADE,
  token text NOT NULL,
  method text NOT NULL,
  path text NOT NULL,
  source_ip inet,
  headers_json text,
  body text
);

CREATE INDEX IF NOT EXISTS sf_webhook_events_received_at_idx ON sf_webhook_events(received_at DESC);
CREATE INDEX IF NOT EXISTS sf_webhook_events_username_idx ON sf_webhook_events(username, received_at DESC);

CREATE TABLE IF NOT EXISTS sf_snmp_trap_tokens (
  username text PRIMARY KEY REFERENCES sf_users(username) ON UPDATE CASCADE,
  community text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sf_snmp_trap_events (
  id bigserial PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now(),
  username text REFERENCES sf_users(username) ON UPDATE CASCADE,
  source_ip inet,
  community text,
  oid text,
  vars_json text,
  raw_hex text
);

CREATE INDEX IF NOT EXISTS sf_snmp_trap_events_received_at_idx ON sf_snmp_trap_events(received_at DESC);
CREATE INDEX IF NOT EXISTS sf_snmp_trap_events_username_idx ON sf_snmp_trap_events(username, received_at DESC);
