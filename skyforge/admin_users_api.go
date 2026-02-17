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
	Status        string   `json:"status"`
	DeletedOwners int      `json:"deletedOwners"`
	Warnings      []string `json:"warnings,omitempty"`
}

// PurgeUser removes a user and their state (admin only).
//
// This is intended for development environments where you want to rerun
// "first-login" bootstrap (Gitea user/provisioning, default user context, etc).
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

	deletedOwners, warnings, err := purgeUserSQL(ctx, s.db, username)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("purge failed").Err()
	}

	// Best-effort cleanup of file-backed state.
	if contexts, err := s.ownerContextStore.load(); err == nil {
		for _, ws := range contexts {
			if strings.EqualFold(ws.CreatedBy, username) {
				if err := s.ownerContextStore.delete(ws.ID); err != nil {
					warnings = append(warnings, fmt.Sprintf("failed to delete owner context %s: %v", ws.ID, err))
				}
				continue
			}
		}
	} else {
		warnings = append(warnings, fmt.Sprintf("failed to load owner contexts store: %v", err))
	}
	if err := s.userStore.remove(username); err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to update users store: %v", err))
	}
	_ = notifyUsersUpdatePG(ctx, s.db, "*")
	_ = notifyDashboardUpdatePG(ctx, s.db)

	// Best-effort cleanup of Gitea user and repos.
	{
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := purgeGiteaUser(cleanupCtx, s.cfg, username); err != nil {
			log.Printf("purgeGiteaUser(%s): %v", username, err)
		}
	}

	return &PurgeUserResponse{
		Status:        "ok",
		DeletedOwners: deletedOwners,
		Warnings:      warnings,
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

	// Identify owner contexts created by this user so we can delete all
	// owner-level rows before deleting the owner context itself (no cascade).
	ownerIDs := make([]string, 0, 4)
	rows, err := tx.QueryContext(ctx, `SELECT id FROM sf_owner_contexts WHERE created_by = $1`, username)
	if err != nil {
		return rollback(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return rollback(err)
		}
		ownerIDs = append(ownerIDs, id)
	}
	_ = rows.Close()

	// Delete user-level rows first (no cascade on sf_users).
	stmts := []struct {
		label string
		query string
		args  []any
	}{
		{"notifications", `DELETE FROM sf_notifications WHERE username = $1`, []any{username}},
		{"audit_actor", `DELETE FROM sf_audit_log WHERE actor_username = $1 OR impersonated_username = $1`, []any{username}},
		{"owner_members", `DELETE FROM sf_owner_members WHERE username = $1`, []any{username}},
		{"user_variable_groups", `DELETE FROM sf_user_variable_groups WHERE username = $1`, []any{username}},
		{"user_servicenow_configs", `DELETE FROM sf_user_servicenow_configs WHERE username = $1`, []any{username}},
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

	deletedOwners := 0
	if len(ownerIDs) > 0 {
		ownerScopedDeletes := []struct {
			label string
			query string
		}{
			{"owner_cost_snapshots", `DELETE FROM sf_cost_snapshots WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_usage_snapshots", `DELETE FROM sf_usage_snapshots WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_resource_events", `DELETE FROM sf_resource_events WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_resources", `DELETE FROM sf_resources WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_tasks", `DELETE FROM sf_tasks WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_deployments", `DELETE FROM sf_deployments WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_pki_certs", `DELETE FROM sf_pki_certs WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_forward_credentials", `DELETE FROM sf_owner_forward_credentials WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_aws_static_credentials", `DELETE FROM sf_owner_aws_static_credentials WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_azure_credentials", `DELETE FROM sf_owner_azure_credentials WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_gcp_credentials", `DELETE FROM sf_owner_gcp_credentials WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_groups", `DELETE FROM sf_owner_groups WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_variable_groups", `DELETE FROM sf_owner_variable_groups WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_members_all", `DELETE FROM sf_owner_members WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
			{"owner_audit_log", `DELETE FROM sf_audit_log WHERE owner_username IN (SELECT id FROM sf_owner_contexts WHERE created_by = $1)`},
		}
		for _, stmt := range ownerScopedDeletes {
			if _, err := tx.ExecContext(ctx, stmt.query, username); err != nil {
				return rollback(fmt.Errorf("%s: %w", stmt.label, err))
			}
		}

		res, err := tx.ExecContext(ctx, `DELETE FROM sf_owner_contexts WHERE created_by = $1`, username)
		if err != nil {
			return rollback(err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			deletedOwners = int(n)
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sf_users WHERE username = $1`, username); err != nil {
		return rollback(err)
	}

	if err := tx.Commit(); err != nil {
		return rollback(err)
	}
	return deletedOwners, nil, nil
}
