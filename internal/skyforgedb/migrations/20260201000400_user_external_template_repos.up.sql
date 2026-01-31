ALTER TABLE sf_user_settings
  ADD COLUMN IF NOT EXISTS external_template_repos_json text NOT NULL DEFAULT '[]';

