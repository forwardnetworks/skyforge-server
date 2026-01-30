-- Seed Forward device types for Juniper routers/switches.
-- Netlab uses vjunos-* and vmx device keys; Forward expects explicit classic types.

INSERT INTO sf_forward_device_types (device_key, forward_type)
VALUES
  ('vjunos-switch', 'juniper_junos_ssh'),
  ('vjunos-router', 'juniper_junos_ssh'),
  ('vmx',           'juniper_junos_ssh'),
  ('junos',         'juniper_junos_ssh')
ON CONFLICT (device_key) DO UPDATE SET forward_type = EXCLUDED.forward_type;

