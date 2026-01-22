CREATE TABLE IF NOT EXISTS sf_forward_device_types (
  device_key text PRIMARY KEY,
  forward_type text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Seed a few high-value defaults. Users/admin tooling can add/update mappings later.
INSERT INTO sf_forward_device_types (device_key, forward_type)
VALUES
  ('linux', 'linux_os_ssh'),
  ('eos', 'arista_eos_ssh'),
  ('ios', 'cisco_ios_ssh'),
  ('iosv', 'cisco_ios_ssh'),
  ('iol', 'cisco_ios_ssh'),
  ('ioll2', 'cisco_ios_ssh'),
  ('nxos', 'cisco_nxos_ssh'),
  ('asa', 'cisco_asa_ssh'),
  ('asav', 'cisco_asa_ssh'),
  ('iosxe', 'cisco_ios_xe_ssh'),
  ('csr', 'cisco_ios_xe_ssh'),
  ('cat8000v', 'cisco_ios_xe_ssh'),
  ('cisco8000v', 'cisco_ios_xe_ssh'),
  ('iosxr', 'cisco_ios_xr_ssh'),
  ('xr', 'cisco_ios_xr_ssh')
ON CONFLICT (device_key) DO NOTHING;
