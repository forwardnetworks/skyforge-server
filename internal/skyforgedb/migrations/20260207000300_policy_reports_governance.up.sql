-- Policy Reports governance primitives (recert + exceptions).
-- Read-only by design: these tables track review/attestation state, not config changes.

CREATE TABLE IF NOT EXISTS sf_policy_report_recert_campaigns (
  id uuid PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  forward_network_id text NOT NULL,
  snapshot_id text NOT NULL DEFAULT '',
  pack_id text NOT NULL,
  status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED')),
  due_at timestamptz,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_rc_campaigns_ws_idx
  ON sf_policy_report_recert_campaigns(owner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sf_policy_report_recert_assignments (
  id uuid PRIMARY KEY,
  campaign_id uuid NOT NULL REFERENCES sf_policy_report_recert_campaigns(id) ON DELETE CASCADE,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  finding_id text NOT NULL,
  check_id text NOT NULL,
  assignee_username text REFERENCES sf_users(username) ON UPDATE CASCADE,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','ATTESTED','WAIVED')),
  justification text,
  attested_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_rc_assignments_campaign_idx
  ON sf_policy_report_recert_assignments(campaign_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_rc_assignments_ws_finding_idx
  ON sf_policy_report_recert_assignments(owner_id, finding_id);

CREATE TABLE IF NOT EXISTS sf_policy_report_exceptions (
  id uuid PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  finding_id text NOT NULL,
  check_id text NOT NULL,
  status text NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED','APPROVED','REJECTED','EXPIRED')),
  justification text NOT NULL,
  ticket_url text,
  expires_at timestamptz,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  approved_by text REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_exceptions_ws_idx
  ON sf_policy_report_exceptions(owner_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_exceptions_ws_finding_idx
  ON sf_policy_report_exceptions(owner_id, finding_id);

CREATE TABLE IF NOT EXISTS sf_policy_report_audit_log (
  id bigserial PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  actor_username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  action text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_audit_ws_created_idx
  ON sf_policy_report_audit_log(owner_id, created_at DESC);

