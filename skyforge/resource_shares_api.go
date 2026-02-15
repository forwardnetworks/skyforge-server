package skyforge

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ResourceShareRecord struct {
	ResourceType   string `json:"resourceType"`
	ResourceID     string `json:"resourceId"`
	OwnerUsername  string `json:"ownerUsername"`
	SharedUsername string `json:"sharedUsername"`
	Role           string `json:"role"`
	CreatedBy      string `json:"createdBy"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

type ResourceSharesQuery struct {
	ResourceType string `query:"resourceType"`
	ResourceID   string `query:"resourceId"`
}

type ResourceSharesResponse struct {
	Items []ResourceShareRecord `json:"items"`
}

type UpsertResourceShareRequest struct {
	ResourceType   string `json:"resourceType"`
	ResourceID     string `json:"resourceId"`
	SharedUsername string `json:"sharedUsername"`
	Role           string `json:"role"`
}

type DeleteResourceShareQuery struct {
	ResourceType   string `query:"resourceType"`
	ResourceID     string `query:"resourceId"`
	SharedUsername string `query:"sharedUsername"`
}

type ResourceShareActionResponse struct {
	OK bool `json:"ok"`
}

func normalizeResourceType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "deployment", "deployments":
		return "deployment"
	case "forward_network", "forward-network", "forwardnetwork", "network":
		return "forward_network"
	default:
		return ""
	}
}

func normalizeShareRole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "viewer":
		return "viewer"
	case "editor":
		return "editor"
	default:
		return ""
	}
}

func resolveResourceOwnerUsername(ctx context.Context, db *sql.DB, resourceType, resourceID string) (string, error) {
	if db == nil {
		return "", sql.ErrConnDone
	}
	resourceType = normalizeResourceType(resourceType)
	resourceID = strings.TrimSpace(resourceID)
	if resourceType == "" || resourceID == "" {
		return "", errs.B().Code(errs.InvalidArgument).Msg("resourceType and resourceId are required").Err()
	}

	switch resourceType {
	case "deployment":
		var owner sql.NullString
		var createdBy sql.NullString
		err := db.QueryRowContext(ctx, `
SELECT COALESCE(owner_username, ''), COALESCE(created_by, '')
  FROM sf_deployments
 WHERE id = $1
`, resourceID).Scan(&owner, &createdBy)
		if err != nil {
			if err == sql.ErrNoRows {
				return "", errs.B().Code(errs.NotFound).Msg("resource not found").Err()
			}
			return "", err
		}
		if v := strings.ToLower(strings.TrimSpace(owner.String)); v != "" {
			return v, nil
		}
		if v := strings.ToLower(strings.TrimSpace(createdBy.String)); v != "" {
			return v, nil
		}
		return "", errs.B().Code(errs.FailedPrecondition).Msg("resource owner unavailable").Err()
	case "forward_network":
		var owner sql.NullString
		var createdBy sql.NullString
		err := db.QueryRowContext(ctx, `
SELECT COALESCE(owner_username, ''), COALESCE(created_by, '')
  FROM sf_policy_report_forward_networks
 WHERE id::text = $1 OR forward_network_id = $1
 ORDER BY updated_at DESC
 LIMIT 1
`, resourceID).Scan(&owner, &createdBy)
		if err != nil {
			if err == sql.ErrNoRows {
				return "", errs.B().Code(errs.NotFound).Msg("resource not found").Err()
			}
			return "", err
		}
		if v := strings.ToLower(strings.TrimSpace(owner.String)); v != "" {
			return v, nil
		}
		if v := strings.ToLower(strings.TrimSpace(createdBy.String)); v != "" {
			return v, nil
		}
		return "", errs.B().Code(errs.FailedPrecondition).Msg("resource owner unavailable").Err()
	default:
		return "", errs.B().Code(errs.InvalidArgument).Msg("unsupported resourceType").Err()
	}
}

func listResourceShares(ctx context.Context, db *sql.DB, resourceType, resourceID string) ([]ResourceShareRecord, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	rows, err := db.QueryContext(ctx, `
SELECT resource_type, resource_id, owner_username, shared_username, role, created_by, created_at, updated_at
  FROM sf_resource_shares
 WHERE resource_type = $1 AND resource_id = $2
 ORDER BY shared_username ASC
`, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ResourceShareRecord, 0, 8)
	for rows.Next() {
		var rec ResourceShareRecord
		var createdAt time.Time
		var updatedAt time.Time
		if err := rows.Scan(
			&rec.ResourceType,
			&rec.ResourceID,
			&rec.OwnerUsername,
			&rec.SharedUsername,
			&rec.Role,
			&rec.CreatedBy,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		rec.ResourceType = strings.TrimSpace(rec.ResourceType)
		rec.ResourceID = strings.TrimSpace(rec.ResourceID)
		rec.OwnerUsername = strings.ToLower(strings.TrimSpace(rec.OwnerUsername))
		rec.SharedUsername = strings.ToLower(strings.TrimSpace(rec.SharedUsername))
		rec.Role = strings.ToLower(strings.TrimSpace(rec.Role))
		rec.CreatedBy = strings.ToLower(strings.TrimSpace(rec.CreatedBy))
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetResourceShares lists shares for a resource.
//
//encore:api auth method=GET path=/api/shares
func (s *Service) GetResourceShares(ctx context.Context, q *ResourceSharesQuery) (*ResourceSharesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if q == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("resourceType and resourceId are required").Err()
	}
	resourceType := normalizeResourceType(q.ResourceType)
	resourceID := strings.TrimSpace(q.ResourceID)
	if resourceType == "" || resourceID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("resourceType and resourceId are required").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ownerUsername, err := resolveResourceOwnerUsername(ctxReq, s.db, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) && !strings.EqualFold(ownerUsername, user.Username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	items, err := listResourceShares(ctxReq, s.db, resourceType, resourceID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list shares").Err()
	}
	return &ResourceSharesResponse{Items: items}, nil
}

// PutResourceShare creates or updates a share grant for a resource.
//
//encore:api auth method=PUT path=/api/shares
func (s *Service) PutResourceShare(ctx context.Context, req *UpsertResourceShareRequest) (*ResourceSharesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	resourceType := normalizeResourceType(req.ResourceType)
	resourceID := strings.TrimSpace(req.ResourceID)
	sharedUsername := strings.ToLower(strings.TrimSpace(req.SharedUsername))
	role := normalizeShareRole(req.Role)
	if resourceType == "" || resourceID == "" || sharedUsername == "" || role == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("resourceType, resourceId, sharedUsername, and role are required").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ownerUsername, err := resolveResourceOwnerUsername(ctxReq, s.db, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) && !strings.EqualFold(ownerUsername, user.Username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if strings.EqualFold(sharedUsername, ownerUsername) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("cannot share a resource with its owner").Err()
	}

	_, err = s.db.ExecContext(ctxReq, `
INSERT INTO sf_resource_shares (
  resource_type, resource_id, owner_username, shared_username, role, created_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,now(),now())
ON CONFLICT (resource_type, resource_id, shared_username)
DO UPDATE SET
  owner_username=EXCLUDED.owner_username,
  role=EXCLUDED.role,
  updated_at=now()
`, resourceType, resourceID, strings.ToLower(ownerUsername), sharedUsername, role, strings.ToLower(strings.TrimSpace(user.Username)))
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save share").Err()
	}

	items, err := listResourceShares(ctxReq, s.db, resourceType, resourceID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list shares").Err()
	}
	return &ResourceSharesResponse{Items: items}, nil
}

// DeleteResourceShare removes a share grant for a resource.
//
//encore:api auth method=DELETE path=/api/shares
func (s *Service) DeleteResourceShare(ctx context.Context, q *DeleteResourceShareQuery) (*ResourceShareActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if q == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("resourceType, resourceId, and sharedUsername are required").Err()
	}
	resourceType := normalizeResourceType(q.ResourceType)
	resourceID := strings.TrimSpace(q.ResourceID)
	sharedUsername := strings.ToLower(strings.TrimSpace(q.SharedUsername))
	if resourceType == "" || resourceID == "" || sharedUsername == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("resourceType, resourceId, and sharedUsername are required").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ownerUsername, err := resolveResourceOwnerUsername(ctxReq, s.db, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) && !strings.EqualFold(ownerUsername, user.Username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	_, err = s.db.ExecContext(ctxReq, `
DELETE FROM sf_resource_shares
 WHERE resource_type = $1
   AND resource_id = $2
   AND shared_username = $3
`, resourceType, resourceID, sharedUsername)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete share").Err()
	}
	return &ResourceShareActionResponse{OK: true}, nil
}
