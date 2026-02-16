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

type UserOwnerVariableGroupListResponse struct {
	OwnerUsername string               `json:"ownerUsername"`
	Groups        []*UserVariableGroup `json:"groups"`
}

// ListOwnerVariableGroups lists variable groups for a user context.
func (s *Service) ListOwnerVariableGroups(ctx context.Context, id string) (*UserOwnerVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, variables FROM sf_owner_variable_groups WHERE owner_username=$1 ORDER BY name`, pc.context.ID)
	if err != nil {
		log.Printf("variable groups list: %v", err)
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
	sort.Slice(groups, func(i, j int) bool { return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name) })
	return &UserOwnerVariableGroupListResponse{OwnerUsername: pc.context.ID, Groups: groups}, nil
}

// CreateOwnerVariableGroup creates a variable group for a user context.
func (s *Service) CreateOwnerVariableGroup(ctx context.Context, id string, req *UserVariableGroupUpsertRequest) (*UserVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	err = s.db.QueryRowContext(ctx, `INSERT INTO sf_owner_variable_groups (owner_username, name, variables)
VALUES ($1,$2,$3)
RETURNING id`, pc.context.ID, strings.TrimSpace(req.Name), payload).Scan(&groupID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("variable group already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create variable group").Err()
	}
	return &UserVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// UpdateOwnerVariableGroup updates a variable group for a user context.
func (s *Service) UpdateOwnerVariableGroup(ctx context.Context, id string, groupID int, req *UserVariableGroupUpsertRequest) (*UserVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	res, err := s.db.ExecContext(ctx, `UPDATE sf_owner_variable_groups SET name=$1, variables=$2, updated_at=now() WHERE id=$3 AND owner_username=$4`, strings.TrimSpace(req.Name), payload, groupID, pc.context.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return &UserVariableGroup{ID: groupID, Name: strings.TrimSpace(req.Name), Variables: vars}, nil
}

// DeleteOwnerVariableGroup deletes a variable group for a user context.
func (s *Service) DeleteOwnerVariableGroup(ctx context.Context, id string, groupID int) (*UserOwnerVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_owner_variable_groups WHERE id=$1 AND owner_username=$2`, groupID, pc.context.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete variable group").Err()
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("variable group not found").Err()
	}
	return s.ListOwnerVariableGroups(ctx, id)
}
