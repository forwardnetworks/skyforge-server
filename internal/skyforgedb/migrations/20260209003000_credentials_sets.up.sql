-- Single credentials table (initially used for Forward). Secrets are encrypted at rest by the application.

CREATE TABLE IF NOT EXISTS sf_credentials (
  id text PRIMARY KEY,
  owner_username text REFERENCES sf_users(username) ON DELETE CASCADE,
  owner_id text REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  provider text NOT NULL,
  name text NOT NULL,

  -- Forward (and friends): store encrypted-at-rest fields as "enc:" blobs.
  base_url_enc text,
  skip_tls_verify boolean NOT NULL DEFAULT false,
  forward_username_enc text,
  forward_password_enc text,

  collector_id_enc text,
  collector_username_enc text,
  authorization_key_enc text,

  device_username_enc text,
  device_password_enc text,

  jump_host_enc text,
  jump_username_enc text,
  jump_private_key_enc text,
  jump_cert_enc text,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT sf_credentials_owner_chk CHECK (
    (owner_username IS NOT NULL AND owner_id IS NULL) OR
    (owner_username IS NULL AND owner_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS sf_credentials_owner_provider_updated_idx
  ON sf_credentials(owner_username, provider, updated_at DESC);
CREATE INDEX IF NOT EXISTS sf_credentials_owner_provider_updated_idx
  ON sf_credentials(owner_id, provider, updated_at DESC);

ALTER TABLE sf_user_forward_collectors
  ADD COLUMN IF NOT EXISTS credential_id text REFERENCES sf_credentials(id) ON DELETE RESTRICT;

ALTER TABLE sf_policy_report_forward_network_credentials
  ADD COLUMN IF NOT EXISTS credential_id text REFERENCES sf_credentials(id) ON DELETE RESTRICT;

ALTER TABLE sf_owner_forward_credentials
  ADD COLUMN IF NOT EXISTS credential_id text REFERENCES sf_credentials(id) ON DELETE RESTRICT;

-- Allow referencing sf_credentials without duplicating secrets in legacy columns.
ALTER TABLE sf_user_forward_collectors
  ALTER COLUMN base_url DROP NOT NULL,
  ALTER COLUMN forward_username DROP NOT NULL,
  ALTER COLUMN forward_password DROP NOT NULL;

ALTER TABLE sf_policy_report_forward_network_credentials
  ALTER COLUMN base_url_enc DROP NOT NULL,
  ALTER COLUMN forward_username_enc DROP NOT NULL,
  ALTER COLUMN forward_password_enc DROP NOT NULL;

ALTER TABLE sf_owner_forward_credentials
  ALTER COLUMN base_url DROP NOT NULL,
  ALTER COLUMN username DROP NOT NULL,
  ALTER COLUMN password DROP NOT NULL;

-- Backfill: create credential sets for existing rows and link via credential_id.
-- We generate deterministic UUID-ish ids using md5 so the migration is idempotent without extensions.

-- sf_user_forward_collectors -> sf_credentials (user-ownerd)
WITH src AS (
  SELECT
    ufc.id AS collector_config_id,
    ufc.username AS owner_username,
    md5('forward:collector:' || ufc.username || ':' || ufc.id) AS h,
    ufc.name AS name,
    ufc.base_url AS base_url_enc,
    COALESCE(ufc.skip_tls_verify, false) AS skip_tls_verify,
    ufc.forward_username AS forward_username_enc,
    ufc.forward_password AS forward_password_enc,
    ufc.collector_id AS collector_id_enc,
    ufc.collector_username AS collector_username_enc,
    ufc.authorization_key AS authorization_key_enc,
    ufc.created_at AS created_at,
    ufc.updated_at AS updated_at
  FROM sf_user_forward_collectors ufc
  WHERE ufc.credential_id IS NULL
),
ins AS (
  INSERT INTO sf_credentials (
    id, owner_username, provider, name,
    base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
    collector_id_enc, collector_username_enc, authorization_key_enc,
    created_at, updated_at
  )
  SELECT
    substr(h,1,8)||'-'||substr(h,9,4)||'-'||substr(h,13,4)||'-'||substr(h,17,4)||'-'||substr(h,21,12) AS id,
    owner_username,
    'forward' AS provider,
    name,
    base_url_enc,
    skip_tls_verify,
    forward_username_enc,
    forward_password_enc,
    NULLIF(collector_id_enc, ''),
    NULLIF(collector_username_enc, ''),
    NULLIF(authorization_key_enc, ''),
    COALESCE(created_at, now()),
    COALESCE(updated_at, now())
  FROM src
  ON CONFLICT (id) DO NOTHING
  RETURNING id
)
UPDATE sf_user_forward_collectors ufc
SET credential_id = substr(src.h,1,8)||'-'||substr(src.h,9,4)||'-'||substr(src.h,13,4)||'-'||substr(src.h,17,4)||'-'||substr(src.h,21,12)
FROM src
WHERE ufc.id = src.collector_config_id
  AND ufc.username = src.owner_username
  AND ufc.credential_id IS NULL;

-- sf_policy_report_forward_network_credentials -> sf_credentials (user-ownerd)
WITH src AS (
  SELECT
    pr.owner_id,
    pr.username AS owner_username,
    pr.forward_network_id,
    md5('forward:policy-reports:' || pr.owner_id || ':' || pr.username || ':' || pr.forward_network_id) AS h,
    ('policy-reports ' || pr.forward_network_id) AS name,
    pr.base_url_enc AS base_url_enc,
    COALESCE(pr.skip_tls_verify, false) AS skip_tls_verify,
    pr.forward_username_enc AS forward_username_enc,
    pr.forward_password_enc AS forward_password_enc,
    pr.created_at AS created_at,
    pr.updated_at AS updated_at
  FROM sf_policy_report_forward_network_credentials pr
  WHERE pr.credential_id IS NULL
),
ins AS (
  INSERT INTO sf_credentials (
    id, owner_username, provider, name,
    base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
    created_at, updated_at
  )
  SELECT
    substr(h,1,8)||'-'||substr(h,9,4)||'-'||substr(h,13,4)||'-'||substr(h,17,4)||'-'||substr(h,21,12) AS id,
    owner_username,
    'forward' AS provider,
    name,
    base_url_enc,
    skip_tls_verify,
    forward_username_enc,
    forward_password_enc,
    COALESCE(created_at, now()),
    COALESCE(updated_at, now())
  FROM src
  ON CONFLICT (id) DO NOTHING
  RETURNING id
)
UPDATE sf_policy_report_forward_network_credentials pr
SET credential_id = substr(src.h,1,8)||'-'||substr(src.h,9,4)||'-'||substr(src.h,13,4)||'-'||substr(src.h,17,4)||'-'||substr(src.h,21,12)
FROM src
WHERE pr.owner_id = src.owner_id
  AND pr.username = src.owner_username
  AND pr.forward_network_id = src.forward_network_id
  AND pr.credential_id IS NULL;

-- sf_owner_forward_credentials -> sf_credentials (owner-ownerd)
WITH src AS (
  SELECT
    wfc.owner_id,
    md5('forward:owner:' || wfc.owner_id) AS h,
    'owner forward' AS name,
    wfc.base_url AS base_url_enc,
    wfc.username AS forward_username_enc,
    wfc.password AS forward_password_enc,
    wfc.collector_id AS collector_id_enc,
    wfc.collector_username AS collector_username_enc,
    wfc.device_username AS device_username_enc,
    wfc.device_password AS device_password_enc,
    wfc.jump_host AS jump_host_enc,
    wfc.jump_username AS jump_username_enc,
    wfc.jump_private_key AS jump_private_key_enc,
    wfc.jump_cert AS jump_cert_enc,
    wfc.updated_at AS updated_at
  FROM sf_owner_forward_credentials wfc
  WHERE wfc.credential_id IS NULL
),
ins AS (
  INSERT INTO sf_credentials (
    id, owner_id, provider, name,
    base_url_enc, forward_username_enc, forward_password_enc,
    collector_id_enc, collector_username_enc,
    device_username_enc, device_password_enc,
    jump_host_enc, jump_username_enc, jump_private_key_enc, jump_cert_enc,
    created_at, updated_at
  )
  SELECT
    substr(h,1,8)||'-'||substr(h,9,4)||'-'||substr(h,13,4)||'-'||substr(h,17,4)||'-'||substr(h,21,12) AS id,
    owner_id,
    'forward' AS provider,
    name,
    base_url_enc,
    forward_username_enc,
    forward_password_enc,
    NULLIF(collector_id_enc, ''),
    NULLIF(collector_username_enc, ''),
    NULLIF(device_username_enc, ''),
    NULLIF(device_password_enc, ''),
    NULLIF(jump_host_enc, ''),
    NULLIF(jump_username_enc, ''),
    NULLIF(jump_private_key_enc, ''),
    NULLIF(jump_cert_enc, ''),
    now(),
    COALESCE(updated_at, now())
  FROM src
  ON CONFLICT (id) DO NOTHING
  RETURNING id
)
UPDATE sf_owner_forward_credentials wfc
SET credential_id = substr(src.h,1,8)||'-'||substr(src.h,9,4)||'-'||substr(src.h,13,4)||'-'||substr(src.h,17,4)||'-'||substr(src.h,21,12)
FROM src
WHERE wfc.owner_id = src.owner_id
  AND wfc.credential_id IS NULL;
