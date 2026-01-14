package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type PurgeUserRequest struct {
	Username string `json:"username"`
	Confirm  string `json:"confirm"`
}

type PurgeUserResponse struct {
	Status            string   `json:"status"`
	DeletedWorkspaces int      `json:"deletedWorkspaces"`
	Warnings          []string `json:"warnings,omitempty"`
}

// PurgeUser removes a user and their state (admin only).
//
// This is intended for development environments where you want to rerun
// "first-login" bootstrap (Gitea user/provisioning, default workspace, etc).
//
//encore:api auth method=POST path=/api/admin/users/purge tag:admin
func (s *Service) PurgeUser(ctx context.Context, req *PurgeUserRequest) (*PurgeUserResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("user store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	if strings.TrimSpace(req.Confirm) != username {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("confirm must match username").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	deletedWorkspaces, warnings, err := purgeUserSQL(ctx, s.db, username)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("purge failed").Err()
	}

	// Best-effort cleanup of file-backed state.
	if workspaces, err := s.workspaceStore.load(); err == nil {
		next := make([]SkyforgeWorkspace, 0, len(workspaces))
		for _, ws := range workspaces {
			if strings.EqualFold(ws.CreatedBy, username) {
				continue
			}
			next = append(next, ws)
		}
		if err := s.workspaceStore.save(next); err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to update workspaces store: %v", err))
		}
	} else {
		warnings = append(warnings, fmt.Sprintf("failed to load workspaces store: %v", err))
	}
	if err := s.userStore.remove(username); err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to update users store: %v", err))
	}

	// Best-effort cleanup of Gitea user and repos.
	{
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := purgeGiteaUser(cleanupCtx, s.cfg, username); err != nil {
			log.Printf("purgeGiteaUser(%s): %v", username, err)
		}
	}

	return &PurgeUserResponse{
		Status:            "ok",
		DeletedWorkspaces: deletedWorkspaces,
		Warnings:          warnings,
	}, nil
}

func purgeUserSQL(ctx context.Context, db *sql.DB, username string) (int, []string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	rollback := func(err error) (int, []string, error) {
		_ = tx.Rollback()
		return 0, nil, err
	}

	// Identify workspaces created by this user so we can delete all workspace-scoped rows
	// before deleting the workspace itself (no cascade).
	workspaceIDs := make([]string, 0, 4)
	rows, err := tx.QueryContext(ctx, `SELECT id FROM sf_workspaces WHERE created_by = $1`, username)
	if err != nil {
		return rollback(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return rollback(err)
		}
		workspaceIDs = append(workspaceIDs, id)
	}
	_ = rows.Close()

	// Delete user-scoped rows first (no cascade on sf_users).
	stmts := []struct {
		label string
		query string
		args  []any
	}{
		{"notifications", `DELETE FROM sf_notifications WHERE username = $1`, []any{username}},
		{"audit_actor", `DELETE FROM sf_audit_log WHERE actor_username = $1 OR impersonated_username = $1`, []any{username}},
		{"workspace_members", `DELETE FROM sf_workspace_members WHERE username = $1`, []any{username}},
		{"aws_sso_tokens", `DELETE FROM sf_aws_sso_tokens WHERE username = $1`, []any{username}},
		{"dns_tokens", `DELETE FROM sf_dns_tokens WHERE username = $1`, []any{username}},
		{"webhook_tokens", `DELETE FROM sf_webhook_tokens WHERE username = $1`, []any{username}},
		{"webhook_events", `DELETE FROM sf_webhook_events WHERE username = $1`, []any{username}},
		{"snmp_tokens", `DELETE FROM sf_snmp_trap_tokens WHERE username = $1`, []any{username}},
		{"snmp_events", `DELETE FROM sf_snmp_trap_events WHERE username = $1`, []any{username}},
		{"syslog_routes", `DELETE FROM sf_syslog_routes WHERE owner_username = $1`, []any{username}},
		{"pki_certs", `DELETE FROM sf_pki_certs WHERE username = $1`, []any{username}},
		{"pki_ssh_certs", `DELETE FROM sf_pki_ssh_certs WHERE username = $1`, []any{username}},
		{"resources", `DELETE FROM sf_resources WHERE owner_username = $1`, []any{username}},
		{"resource_events", `DELETE FROM sf_resource_events WHERE actor_username = $1 OR impersonated_username = $1`, []any{username}},
		{"deployments_created", `DELETE FROM sf_deployments WHERE created_by = $1`, []any{username}},
		{"tasks_created", `DELETE FROM sf_tasks WHERE created_by = $1`, []any{username}},
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt.query, stmt.args...); err != nil {
			return rollback(fmt.Errorf("%s: %w", stmt.label, err))
		}
	}

	deletedWorkspaces := 0
	if len(workspaceIDs) > 0 {
		workspaceScopedDeletes := []struct {
			label string
			query string
		}{
			{"workspace_cost_snapshots", `DELETE FROM sf_cost_snapshots WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_usage_snapshots", `DELETE FROM sf_usage_snapshots WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_resource_events", `DELETE FROM sf_resource_events WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_resources", `DELETE FROM sf_resources WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_tasks", `DELETE FROM sf_tasks WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_deployments", `DELETE FROM sf_deployments WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_pki_certs", `DELETE FROM sf_pki_certs WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_forward_credentials", `DELETE FROM sf_workspace_forward_credentials WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_aws_static_credentials", `DELETE FROM sf_workspace_aws_static_credentials WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_azure_credentials", `DELETE FROM sf_workspace_azure_credentials WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_gcp_credentials", `DELETE FROM sf_workspace_gcp_credentials WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_groups", `DELETE FROM sf_workspace_groups WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_variable_groups", `DELETE FROM sf_workspace_variable_groups WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_members_all", `DELETE FROM sf_workspace_members WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
			{"workspace_audit_log", `DELETE FROM sf_audit_log WHERE workspace_id IN (SELECT id FROM sf_workspaces WHERE created_by = $1)`},
		}
		for _, stmt := range workspaceScopedDeletes {
			if _, err := tx.ExecContext(ctx, stmt.query, username); err != nil {
				return rollback(fmt.Errorf("%s: %w", stmt.label, err))
			}
		}

		res, err := tx.ExecContext(ctx, `DELETE FROM sf_workspaces WHERE created_by = $1`, username)
		if err != nil {
			return rollback(err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			deletedWorkspaces = int(n)
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sf_users WHERE username = $1`, username); err != nil {
		return rollback(err)
	}

	if err := tx.Commit(); err != nil {
		return rollback(err)
	}
	return deletedWorkspaces, nil, nil
}
