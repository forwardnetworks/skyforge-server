package skyforge

import (
	"context"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type AdminAuditParams struct {
	Limit string `query:"limit" encore:"optional"`
}

type AdminAuditResponse struct {
	Events    []AuditEvent `json:"events"`
	Limit     int          `json:"limit"`
	Timestamp string       `json:"timestamp"`
}

type AdminImpersonateStatusResponse struct {
	EffectiveUsername string `json:"effectiveUsername"`
	ActorUsername     string `json:"actorUsername,omitempty"`
	Impersonating     bool   `json:"impersonating"`
	Time              string `json:"time"`
}

// GetAdminAudit returns audit events (admin only).
//
//encore:api auth method=GET path=/api/admin/audit tag:admin
func (s *Service) GetAdminAudit(ctx context.Context, params *AdminAuditParams) (*AdminAuditResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("audit log unavailable (db not configured)").Err()
	}
	limit := 200
	if params != nil {
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 1000 {
				limit = v
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, created_at, actor_username, actor_is_admin, COALESCE(impersonated_username,''), action, COALESCE(project_id,''), COALESCE(details,'')
FROM sf_audit_log ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load audit log").Err()
	}
	defer rows.Close()
	events := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.ActorUsername, &e.ActorIsAdmin, &e.ImpersonatedUser, &e.Action, &e.ProjectID, &e.Details); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load audit log").Err()
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load audit log").Err()
	}
	return &AdminAuditResponse{
		Events:    events,
		Limit:     limit,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetAdminAuditV1 returns audit events (v1 alias).
//
//encore:api auth method=GET path=/api/v1/admin/audit tag:admin
func (s *Service) GetAdminAuditV1(ctx context.Context, params *AdminAuditParams) (*AdminAuditResponse, error) {
	return s.GetAdminAudit(ctx, params)
}

// GetAdminImpersonateStatus returns current impersonation status (admin only).
//
//encore:api auth method=GET path=/api/admin/impersonate/status tag:admin
func (s *Service) GetAdminImpersonateStatus(ctx context.Context) (*AdminImpersonateStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	_ = ctx
	return &AdminImpersonateStatusResponse{
		EffectiveUsername: user.Username,
		ActorUsername:     user.ActorUsername,
		Impersonating:     user.Impersonating,
		Time:              time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetAdminImpersonateStatusV1 returns current impersonation status (v1 alias).
//
//encore:api auth method=GET path=/api/v1/admin/impersonate/status tag:admin
func (s *Service) GetAdminImpersonateStatusV1(ctx context.Context) (*AdminImpersonateStatusResponse, error) {
	return s.GetAdminImpersonateStatus(ctx)
}
