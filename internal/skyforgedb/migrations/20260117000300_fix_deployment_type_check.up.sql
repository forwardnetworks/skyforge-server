UPDATE sf_deployments
SET type='terraform'
WHERE type='tofu';

ALTER TABLE sf_deployments
  DROP CONSTRAINT IF EXISTS sf_deployments_type_check;

ALTER TABLE sf_deployments
  ADD CONSTRAINT sf_deployments_type_check
  CHECK ((type = ANY (ARRAY[
    'terraform'::text,
    'netlab'::text,
    'netlab-c9s'::text,
    'eve_ng'::text,
    'containerlab'::text,
    'clabernetes'::text
  ])));
