-- Restore legacy alias key for Juniper SRX if needed.

INSERT INTO sf_forward_device_types (device_key, forward_type)
VALUES ('srx', 'juniper_srx_ssh')
ON CONFLICT (device_key) DO NOTHING;
