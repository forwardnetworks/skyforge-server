CREATE TABLE IF NOT EXISTS sf_user_ai_generations (
  id uuid PRIMARY KEY,
  username text NOT NULL REFERENCES sf_users(username) ON DELETE CASCADE,
  provider text NOT NULL,
  kind text NOT NULL,
  prompt text NOT NULL,
  content text NOT NULL,
  warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sf_user_ai_generations_user_created ON sf_user_ai_generations(username, created_at DESC);

