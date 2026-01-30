-- Seed Forward device types for firewall platforms used by Skyforge.
-- Keep this additive (do not edit earlier migrations).

INSERT INTO sf_forward_device_types (device_key, forward_type)
VALUES
  ('fortios', 'fortinet_ssh'),
  ('fortinet', 'fortinet_ssh'),
  ('vsrx', 'juniper_srx_ssh'),
  ('srx', 'juniper_srx_ssh')
ON CONFLICT (device_key) DO NOTHING;

