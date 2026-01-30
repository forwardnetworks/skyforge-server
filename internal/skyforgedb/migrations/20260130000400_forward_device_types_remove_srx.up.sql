-- Collapse Juniper SRX keys to a single canonical device_key (vsrx).

DELETE FROM sf_forward_device_types WHERE device_key = 'srx';
