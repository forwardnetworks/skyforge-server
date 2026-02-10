-- Add default Forward credential + network id pointers to user settings.
-- This lets the UI present a single "Forward account" in My Settings while
-- keeping secrets stored in sf_credentials (provider='forward').

ALTER TABLE sf_user_settings
  ADD COLUMN IF NOT EXISTS default_forward_credential_id text,
  ADD COLUMN IF NOT EXISTS default_forward_network_id text NOT NULL DEFAULT '';

