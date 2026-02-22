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

type UserVariableGroup struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

type UserVariableGroupListResponse struct {
	Groups []*UserVariableGroup `json:"groups"`
}

type UserVariableGroupUpsertRequest struct {
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

// ListUserVariableGroups lists variable groups for the current user.
//
//encore:api auth method=GET path=/api/me/variable-groups
func (s *Service) ListUserVariableGroups(ctx context.Context) (*UserVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, variables FROM sf_user_variable_groups WHERE username=$1 ORDER BY name`, user.Username)
	if err != nil {
		log.Printf("user variable groups list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	defer rows.Close()

	groups := []*UserVariableGroup{}
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
		groups = append(groups, &UserVariableGroup{ID: idVal, Name: name, Variables: vars})
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	sort.Slice(groups, func(i, j int) bool {
		return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name)
	})
	return &UserVariableGroupListResponse{Groups: groups}, nil
}

// CreateUserVariableGroup creates a variable group for the current user.
//
//encore:api auth method=POST path=/api/me/variable-groups
func (s *Service) CreateUserVariableGroup(ctx context.Context, req *UserVariableGroupUpsertRequest) (*UserVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
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
	err = s.db.QueryRowContext(ctx, `INSERT INTO sf_user_variable_groups (username, name, variables)
VALUES ($1,$2,$3)
RETURNING id`, user.Username, strings.TrimSpace(req.Name), payload).Scan(&groupID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("variable group already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create variable group").Err()
	}
	return &UserVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// UpdateUserVariableGroup updates a variable group for the current user.
//
//encore:api auth method=PUT path=/api/me/variable-groups/:groupID
func (s *Service) UpdateUserVariableGroup(ctx context.Context, groupID int, req *UserVariableGroupUpsertRequest) (*UserVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
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
	res, err := s.db.ExecContext(ctx, `UPDATE sf_user_variable_groups SET name=$1, variables=$2, updated_at=now() WHERE id=$3 AND username=$4`, strings.TrimSpace(req.Name), payload, groupID, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return &UserVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// DeleteUserVariableGroup deletes a variable group for the current user.
//
//encore:api auth method=DELETE path=/api/me/variable-groups/:groupID
func (s *Service) DeleteUserVariableGroup(ctx context.Context, groupID int) (*UserVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_user_variable_groups WHERE id=$1 AND username=$2`, groupID, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return s.ListUserVariableGroups(ctx)
}
