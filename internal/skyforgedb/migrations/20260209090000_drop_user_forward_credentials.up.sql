-- Drop legacy single-row Forward credentials table.
-- Before dropping, migrate any remaining rows into sf_credentials + sf_user_forward_collectors
-- so existing installs keep working after the table removal.

-- Migrate only for users that have no collector configs yet.
WITH legacy AS (
  SELECT
    u.username,
    md5('forward:legacy-collector-config:' || u.username) AS cfg_h,
    md5('forward:legacy-credential-set:' || u.username) AS cred_h,
    u.base_url AS base_url_enc,
    COALESCE(u.skip_tls_verify, false) AS skip_tls_verify,
    u.forward_username AS forward_username_enc,
    u.forward_password AS forward_password_enc,
    COALESCE(u.collector_id, '') AS collector_id_enc,
    COALESCE(u.collector_username, '') AS collector_username_enc,
    COALESCE(u.authorization_key, '') AS authorization_key_enc,
    COALESCE(u.updated_at, now()) AS updated_at
  FROM sf_user_forward_credentials u
  WHERE NOT EXISTS (
    SELECT 1 FROM sf_user_forward_collectors c WHERE c.username=u.username
  )
),
cred_ins AS (
  INSERT INTO sf_credentials (
    id, owner_username, workspace_id, provider, name,
    base_url_enc, skip_tls_verify, forward_username_enc, forward_password_enc,
    collector_id_enc, collector_username_enc, authorization_key_enc,
    created_at, updated_at
  )
  SELECT
    substr(cred_h,1,8)||'-'||substr(cred_h,9,4)||'-'||substr(cred_h,13,4)||'-'||substr(cred_h,17,4)||'-'||substr(cred_h,21,12) AS id,
    username,
    NULL,
    'forward',
    'Collector: Default',
    base_url_enc,
    skip_tls_verify,
    forward_username_enc,
    forward_password_enc,
    NULLIF(collector_id_enc,''),
    NULLIF(collector_username_enc,''),
    NULLIF(authorization_key_enc,''),
    updated_at,
    updated_at
  FROM legacy
  ON CONFLICT (id) DO NOTHING
  RETURNING id
),
cfg_ins AS (
  INSERT INTO sf_user_forward_collectors (
    id, username, name,
    credential_id,
    base_url, skip_tls_verify, forward_username, forward_password,
    collector_id, collector_username, authorization_key,
    created_at, updated_at, is_default
  )
  SELECT
    substr(cfg_h,1,8)||'-'||substr(cfg_h,9,4)||'-'||substr(cfg_h,13,4)||'-'||substr(cfg_h,17,4)||'-'||substr(cfg_h,21,12) AS id,
    username,
    'Default',
    substr(cred_h,1,8)||'-'||substr(cred_h,9,4)||'-'||substr(cred_h,13,4)||'-'||substr(cred_h,17,4)||'-'||substr(cred_h,21,12) AS credential_id,
    NULL,
    skip_tls_verify,
    NULL, NULL,
    NULL, NULL, NULL,
    updated_at,
    updated_at,
    true
  FROM legacy
  ON CONFLICT (id) DO NOTHING
  RETURNING id, username
)
INSERT INTO sf_user_settings (user_id, default_forward_collector_config_id, default_env_json, external_template_repos_json, updated_at)
SELECT username, id, '[]', '[]', now()
FROM cfg_ins
ON CONFLICT (user_id) DO UPDATE SET
  default_forward_collector_config_id=EXCLUDED.default_forward_collector_config_id,
  updated_at=now();

DROP TABLE IF EXISTS sf_user_forward_credentials;

