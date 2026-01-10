DO $$
BEGIN
  IF to_regclass('sf_projects') IS NOT NULL THEN
    BEGIN
      ALTER TABLE sf_projects RENAME COLUMN tofu_init_template_id TO terraform_init_template_id;
    EXCEPTION WHEN undefined_column THEN
      NULL;
    END;

    BEGIN
      ALTER TABLE sf_projects RENAME COLUMN tofu_plan_template_id TO terraform_plan_template_id;
    EXCEPTION WHEN undefined_column THEN
      NULL;
    END;

    BEGIN
      ALTER TABLE sf_projects RENAME COLUMN tofu_apply_template_id TO terraform_apply_template_id;
    EXCEPTION WHEN undefined_column THEN
      NULL;
    END;
  END IF;

  IF to_regclass('sf_workspaces') IS NOT NULL THEN
    BEGIN
      ALTER TABLE sf_workspaces RENAME COLUMN tofu_init_template_id TO terraform_init_template_id;
    EXCEPTION WHEN undefined_column THEN
      NULL;
    END;

    BEGIN
      ALTER TABLE sf_workspaces RENAME COLUMN tofu_plan_template_id TO terraform_plan_template_id;
    EXCEPTION WHEN undefined_column THEN
      NULL;
    END;

    BEGIN
      ALTER TABLE sf_workspaces RENAME COLUMN tofu_apply_template_id TO terraform_apply_template_id;
    EXCEPTION WHEN undefined_column THEN
      NULL;
    END;
  END IF;
END $$;

UPDATE sf_deployments SET type='terraform' WHERE type='tofu';

ALTER TABLE sf_deployments DROP CONSTRAINT IF EXISTS sf_deployments_type_check;
ALTER TABLE sf_deployments ADD CONSTRAINT sf_deployments_type_check CHECK (type IN ('terraform','netlab','labpp','containerlab'));
