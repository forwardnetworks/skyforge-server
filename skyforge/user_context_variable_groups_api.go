package skyforge

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserContextVariableGroup struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

type UserContextVariableGroupListResponse struct {
	UserContextID string                      `json:"userContextId"`
	Groups        []*UserContextVariableGroup `json:"groups"`
}

type UserContextVariableGroupUpsertRequest struct {
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

// ListUserContextVariableGroups lists variable groups for a user context.
//
//encore:api auth method=GET path=/api/user-contexts/:id/variable-groups
func (s *Service) ListUserContextVariableGroups(ctx context.Context, id string) (*UserContextVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, variables FROM sf_workspace_variable_groups WHERE workspace_id=$1 ORDER BY name`, pc.userContext.ID)
	if err != nil {
		log.Printf("variable groups list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	defer rows.Close()

	groups := []*UserContextVariableGroup{}
	for rows.Next() {
		var (
			idVal int
			name  string
			raw   []byte
		)
		if err := rows.Scan(&idVal, &name, &raw); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode variable groups").Err()
		}
		vars := map[string]string{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &vars)
		}
		groups = append(groups, &UserContextVariableGroup{ID: idVal, Name: name, Variables: vars})
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	sort.Slice(groups, func(i, j int) bool { return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name) })
	return &UserContextVariableGroupListResponse{UserContextID: pc.userContext.ID, Groups: groups}, nil
}

// CreateUserContextVariableGroup creates a variable group for a user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/variable-groups
func (s *Service) CreateUserContextVariableGroup(ctx context.Context, id string, req *UserContextVariableGroupUpsertRequest) (*UserContextVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	vars := req.Variables
	if vars == nil {
		vars = map[string]string{}
	}
	payload, err := json.Marshal(vars)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("failed to encode variables").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var groupID int
	err = s.db.QueryRowContext(ctx, `INSERT INTO sf_workspace_variable_groups (workspace_id, name, variables)
VALUES ($1,$2,$3)
RETURNING id`, pc.userContext.ID, strings.TrimSpace(req.Name), payload).Scan(&groupID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("variable group already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create variable group").Err()
	}
	return &UserContextVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// UpdateUserContextVariableGroup updates a variable group for a user context.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/variable-groups/:groupID
func (s *Service) UpdateUserContextVariableGroup(ctx context.Context, id string, groupID int, req *UserContextVariableGroupUpsertRequest) (*UserContextVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	vars := req.Variables
	if vars == nil {
		vars = map[string]string{}
	}
	payload, err := json.Marshal(vars)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("failed to encode variables").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `UPDATE sf_workspace_variable_groups SET name=$1, variables=$2, updated_at=now() WHERE id=$3 AND workspace_id=$4`, strings.TrimSpace(req.Name), payload, groupID, pc.userContext.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return &UserContextVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// DeleteUserContextVariableGroup deletes a variable group for a user context.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/variable-groups/:groupID
func (s *Service) DeleteUserContextVariableGroup(ctx context.Context, id string, groupID int) (*UserContextVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_workspace_variable_groups WHERE id=$1 AND workspace_id=$2`, groupID, pc.userContext.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return s.ListUserContextVariableGroups(ctx, id)
}
