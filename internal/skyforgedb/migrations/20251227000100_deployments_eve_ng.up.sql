ALTER TABLE sf_deployments
  DROP CONSTRAINT IF EXISTS sf_deployments_type_check;

ALTER TABLE sf_deployments
  ADD CONSTRAINT sf_deployments_type_check CHECK (type IN ('terraform','netlab','eve_ng'));
