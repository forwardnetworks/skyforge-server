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

type WorkspaceVariableGroup struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

type WorkspaceVariableGroupListResponse struct {
	WorkspaceID string                    `json:"userId"`
	Groups      []*WorkspaceVariableGroup `json:"groups"`
}

type WorkspaceVariableGroupUpsertRequest struct {
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

// ListWorkspaceVariableGroups lists variable groups for a workspace.
//
//encore:api auth method=GET path=/api/users/:id/variable-groups
func (s *Service) ListWorkspaceVariableGroups(ctx context.Context, id string) (*WorkspaceVariableGroupListResponse, error) {
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, variables FROM sf_workspace_variable_groups WHERE user_id=$1 ORDER BY name`, pc.workspace.ID)
	if err != nil {
		log.Printf("variable groups list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	defer rows.Close()

	groups := []*WorkspaceVariableGroup{}
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
		groups = append(groups, &WorkspaceVariableGroup{ID: idVal, Name: name, Variables: vars})
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query variable groups").Err()
	}
	sort.Slice(groups, func(i, j int) bool { return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name) })
	return &WorkspaceVariableGroupListResponse{WorkspaceID: pc.workspace.ID, Groups: groups}, nil
}

// CreateWorkspaceVariableGroup creates a variable group for a workspace.
//
//encore:api auth method=POST path=/api/users/:id/variable-groups
func (s *Service) CreateWorkspaceVariableGroup(ctx context.Context, id string, req *WorkspaceVariableGroupUpsertRequest) (*WorkspaceVariableGroup, error) {
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
	err = s.db.QueryRowContext(ctx, `INSERT INTO sf_workspace_variable_groups (user_id, name, variables)
VALUES ($1,$2,$3)
RETURNING id`, pc.workspace.ID, strings.TrimSpace(req.Name), payload).Scan(&groupID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("variable group already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create variable group").Err()
	}
	return &WorkspaceVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// UpdateWorkspaceVariableGroup updates a variable group for a workspace.
//
//encore:api auth method=PUT path=/api/users/:id/variable-groups/:groupID
func (s *Service) UpdateWorkspaceVariableGroup(ctx context.Context, id string, groupID int, req *WorkspaceVariableGroupUpsertRequest) (*WorkspaceVariableGroup, error) {
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
	res, err := s.db.ExecContext(ctx, `UPDATE sf_workspace_variable_groups SET name=$1, variables=$2, updated_at=now() WHERE id=$3 AND user_id=$4`, strings.TrimSpace(req.Name), payload, groupID, pc.workspace.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return &WorkspaceVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// DeleteWorkspaceVariableGroup deletes a variable group for a workspace.
//
//encore:api auth method=DELETE path=/api/users/:id/variable-groups/:groupID
func (s *Service) DeleteWorkspaceVariableGroup(ctx context.Context, id string, groupID int) (*WorkspaceVariableGroupListResponse, error) {
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_workspace_variable_groups WHERE id=$1 AND user_id=$2`, groupID, pc.workspace.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return s.ListWorkspaceVariableGroups(ctx, id)
}
