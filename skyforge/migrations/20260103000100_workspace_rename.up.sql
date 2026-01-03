ALTER TABLE sf_projects RENAME TO sf_workspaces;
ALTER TABLE sf_workspaces RENAME COLUMN legacy_project_id TO legacy_workspace_id;

ALTER TABLE sf_project_members RENAME TO sf_workspace_members;
ALTER TABLE sf_workspace_members RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_project_groups RENAME TO sf_workspace_groups;
ALTER TABLE sf_workspace_groups RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_project_aws_static_credentials RENAME TO sf_workspace_aws_static_credentials;
ALTER TABLE sf_workspace_aws_static_credentials RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_project_azure_credentials RENAME TO sf_workspace_azure_credentials;
ALTER TABLE sf_workspace_azure_credentials RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_project_gcp_credentials RENAME TO sf_workspace_gcp_credentials;
ALTER TABLE sf_workspace_gcp_credentials RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_project_forward_credentials RENAME TO sf_workspace_forward_credentials;
ALTER TABLE sf_workspace_forward_credentials RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_project_variable_groups RENAME TO sf_workspace_variable_groups;
ALTER TABLE sf_workspace_variable_groups RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_deployments RENAME COLUMN project_id TO workspace_id;
ALTER TABLE sf_deployments RENAME COLUMN last_task_project_id TO last_task_workspace_id;

ALTER TABLE sf_tasks RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_resources RENAME COLUMN project_id TO workspace_id;
ALTER TABLE sf_resource_events RENAME COLUMN project_id TO workspace_id;
ALTER TABLE sf_cost_snapshots RENAME COLUMN project_id TO workspace_id;
ALTER TABLE sf_usage_snapshots RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_pki_certs RENAME COLUMN project_id TO workspace_id;
ALTER TABLE sf_pki_ssh_certs RENAME COLUMN project_id TO workspace_id;

ALTER TABLE sf_audit_log RENAME COLUMN project_id TO workspace_id;

ALTER INDEX IF EXISTS sf_projects_created_by_idx RENAME TO sf_workspaces_created_by_idx;
ALTER INDEX IF EXISTS sf_project_members_user_idx RENAME TO sf_workspace_members_user_idx;
ALTER INDEX IF EXISTS sf_project_groups_project_idx RENAME TO sf_workspace_groups_workspace_idx;
ALTER INDEX IF EXISTS sf_resources_project_idx RENAME TO sf_resources_workspace_idx;
ALTER INDEX IF EXISTS sf_resource_events_project_idx RENAME TO sf_resource_events_workspace_idx;
ALTER INDEX IF EXISTS sf_cost_snapshots_project_idx RENAME TO sf_cost_snapshots_workspace_idx;
ALTER INDEX IF EXISTS sf_usage_snapshots_project_idx RENAME TO sf_usage_snapshots_workspace_idx;
ALTER INDEX IF EXISTS sf_deployments_project_name_uq RENAME TO sf_deployments_workspace_name_uq;
ALTER INDEX IF EXISTS sf_deployments_project_idx RENAME TO sf_deployments_workspace_idx;
ALTER INDEX IF EXISTS sf_pki_certs_project_idx RENAME TO sf_pki_certs_workspace_idx;
ALTER INDEX IF EXISTS sf_pki_ssh_certs_project_idx RENAME TO sf_pki_ssh_certs_workspace_idx;
ALTER INDEX IF EXISTS sf_tasks_project_idx RENAME TO sf_tasks_workspace_idx;
ALTER INDEX IF EXISTS sf_project_variable_groups_project_idx RENAME TO sf_workspace_variable_groups_workspace_idx;
ALTER INDEX IF EXISTS sf_project_variable_groups_name_uq RENAME TO sf_workspace_variable_groups_name_uq;
