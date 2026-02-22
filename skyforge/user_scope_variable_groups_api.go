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

type UserScopeVariableGroup struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

type UserScopeVariableGroupListResponse struct {
	UserScopeID string                    `json:"userId"`
	Groups      []*UserScopeVariableGroup `json:"groups"`
}

type UserScopeVariableGroupUpsertRequest struct {
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

// ListUserScopeVariableGroups lists variable groups for a user scope.
//
//encore:api auth method=GET path=/api/users/:id/variable-groups
func (s *Service) ListUserScopeVariableGroups(ctx context.Context, id string) (*UserScopeVariableGroupListResponse, error) {
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, variables FROM sf_user_scope_variable_groups WHERE user_id=$1 ORDER BY name`, pc.userScope.ID)
	if err != nil {
		log.Printf("variable groups list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	defer rows.Close()

	groups := []*UserScopeVariableGroup{}
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
		groups = append(groups, &UserScopeVariableGroup{ID: idVal, Name: name, Variables: vars})
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	sort.Slice(groups, func(i, j int) bool { return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name) })
	return &UserScopeVariableGroupListResponse{UserScopeID: pc.userScope.ID, Groups: groups}, nil
}

// CreateUserScopeVariableGroup creates a variable group for a user scope.
//
//encore:api auth method=POST path=/api/users/:id/variable-groups
func (s *Service) CreateUserScopeVariableGroup(ctx context.Context, id string, req *UserScopeVariableGroupUpsertRequest) (*UserScopeVariableGroup, error) {
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
	err = s.db.QueryRowContext(ctx, `INSERT INTO sf_user_scope_variable_groups (user_id, name, variables)
VALUES ($1,$2,$3)
RETURNING id`, pc.userScope.ID, strings.TrimSpace(req.Name), payload).Scan(&groupID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("variable group already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create variable group").Err()
	}
	return &UserScopeVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// UpdateUserScopeVariableGroup updates a variable group for a user scope.
//
//encore:api auth method=PUT path=/api/users/:id/variable-groups/:groupID
func (s *Service) UpdateUserScopeVariableGroup(ctx context.Context, id string, groupID int, req *UserScopeVariableGroupUpsertRequest) (*UserScopeVariableGroup, error) {
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
	res, err := s.db.ExecContext(ctx, `UPDATE sf_user_scope_variable_groups SET name=$1, variables=$2, updated_at=now() WHERE id=$3 AND user_id=$4`, strings.TrimSpace(req.Name), payload, groupID, pc.userScope.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return &UserScopeVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// DeleteUserScopeVariableGroup deletes a variable group for a user scope.
//
//encore:api auth method=DELETE path=/api/users/:id/variable-groups/:groupID
func (s *Service) DeleteUserScopeVariableGroup(ctx context.Context, id string, groupID int) (*UserScopeVariableGroupListResponse, error) {
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_user_scope_variable_groups WHERE id=$1 AND user_id=$2`, groupID, pc.userScope.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return s.ListUserScopeVariableGroups(ctx, id)
}
