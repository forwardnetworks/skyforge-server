CREATE TABLE IF NOT EXISTS sf_forward_device_types (
  device_key text PRIMARY KEY,
  forward_type text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Seed a few high-value defaults. Users/admin tooling can add/update mappings later.
INSERT INTO sf_forward_device_types (device_key, forward_type)
VALUES
  ('linux', 'linux_os_ssh'),
  ('eos', 'arista_eos_ssh')
ON CONFLICT (device_key) DO NOTHING;

