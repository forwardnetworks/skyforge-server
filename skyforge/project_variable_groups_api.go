package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type ProjectVariableGroup struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

type ProjectVariableGroupListResponse struct {
	ProjectID string               `json:"projectId"`
	Groups    []*ProjectVariableGroup `json:"groups"`
}

type ProjectVariableGroupUpsertRequest struct {
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

// ListProjectVariableGroups lists Semaphore environments for a project.
//
//encore:api auth method=GET path=/api/projects/:id/variable-groups
func (s *Service) ListProjectVariableGroups(ctx context.Context, id string) (*ProjectVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("project is missing semaphore wiring").Err()
	}

	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, body, err := semaphoreDo(semaphoreCfg, http.MethodGet, fmt.Sprintf("/project/%d/environment", pc.project.SemaphoreProjectID), nil)
	if err != nil {
		log.Printf("variable groups list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp.StatusCode >= 400 {
		return nil, errs.B().Code(errs.Unavailable).Msg(strings.TrimSpace(string(body))).Err()
	}
	var envs []map[string]any
	if err := json.Unmarshal(body, &envs); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to decode semaphore environments").Err()
	}

	out := make([]*ProjectVariableGroup, 0, len(envs))
	for _, e := range envs {
		idVal, _ := e["id"].(float64)
		name, _ := e["name"].(string)
		rawEnv, _ := e["env"].(string)
		var vars map[string]string
		_ = json.Unmarshal([]byte(rawEnv), &vars)
		out = append(out, &ProjectVariableGroup{
			ID:        int(idVal),
			Name:      name,
			Variables: vars,
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return &ProjectVariableGroupListResponse{ProjectID: pc.project.ID, Groups: out}, nil
}

// CreateProjectVariableGroup creates a Semaphore environment for a project.
//
//encore:api auth method=POST path=/api/projects/:id/variable-groups
func (s *Service) CreateProjectVariableGroup(ctx context.Context, id string, req *ProjectVariableGroupUpsertRequest) (*ProjectVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("project is missing semaphore wiring").Err()
	}
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}

	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	vars := req.Variables
	if vars == nil {
		vars = map[string]string{}
	}
	payload := map[string]any{
		"name":       name,
		"project_id": pc.project.SemaphoreProjectID,
		"json":       "{}",
		"env":        string(mustJSON(vars)),
	}
	resp, body, err := semaphoreDo(semaphoreCfg, http.MethodPost, fmt.Sprintf("/project/%d/environment", pc.project.SemaphoreProjectID), payload)
	if err != nil {
		log.Printf("variable groups create: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, errs.B().Code(errs.Unavailable).Msg(strings.TrimSpace(string(body))).Err()
	}
	var created map[string]any
	_ = json.Unmarshal(body, &created)
	idAny, _ := created["id"].(float64)
	return &ProjectVariableGroup{ID: int(idAny), Name: name, Variables: vars}, nil
}

// UpdateProjectVariableGroup updates a Semaphore environment for a project.
//
//encore:api auth method=PUT path=/api/projects/:id/variable-groups/:groupID
func (s *Service) UpdateProjectVariableGroup(ctx context.Context, id string, groupID int, req *ProjectVariableGroupUpsertRequest) (*ProjectVariableGroup, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("project is missing semaphore wiring").Err()
	}
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	vars := req.Variables
	if vars == nil {
		vars = map[string]string{}
	}
	payload := map[string]any{
		"id":         groupID,
		"name":       name,
		"project_id": pc.project.SemaphoreProjectID,
		"json":       "{}",
		"env":        string(mustJSON(vars)),
	}
	resp, body, err := semaphoreDo(semaphoreCfg, http.MethodPut, fmt.Sprintf("/project/%d/environment/%d", pc.project.SemaphoreProjectID, groupID), payload)
	if err != nil {
		log.Printf("variable groups update: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return nil, errs.B().Code(errs.Unavailable).Msg(strings.TrimSpace(string(body))).Err()
	}
	return &ProjectVariableGroup{ID: groupID, Name: name, Variables: vars}, nil
}

// DeleteProjectVariableGroup deletes a Semaphore environment for a project.
//
//encore:api auth method=DELETE path=/api/projects/:id/variable-groups/:groupID
func (s *Service) DeleteProjectVariableGroup(ctx context.Context, id string, groupID int) (*ProjectVariableGroupListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if pc.project.SemaphoreProjectID == 0 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("project is missing semaphore wiring").Err()
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	resp, body, err := semaphoreDo(semaphoreCfg, http.MethodDelete, fmt.Sprintf("/project/%d/environment/%d", pc.project.SemaphoreProjectID, groupID), nil)
	if err != nil {
		log.Printf("variable groups delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return nil, errs.B().Code(errs.Unavailable).Msg(strings.TrimSpace(string(body))).Err()
	}
	return s.ListProjectVariableGroups(ctx, id)
}

