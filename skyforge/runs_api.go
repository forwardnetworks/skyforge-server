package skyforge

import (
	"context"
	"log"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

type RunsListParams struct {
	WorkspaceID string `query:"workspace_id" encore:"optional"`
	Limit       string `query:"limit" encore:"optional"`
	Owner       string `query:"owner" encore:"optional"`
}

type RunsListResponse struct {
	User  string    `json:"user"`
	Tasks []JSONMap `json:"tasks"`
}

// GetRuns returns recent runs from native Skyforge tasks.
//
//encore:api auth method=GET path=/api/runs tag:list-runs
func (s *Service) GetRuns(ctx context.Context, params *RunsListParams) (*RunsListResponse, error) {
	runListRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	limit := 5
	if params != nil && strings.TrimSpace(params.Limit) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(params.Limit)); err == nil && v > 0 {
			limit = v
		}
	}

	workspace, err := s.resolveWorkspaceForUser(ctx, user, "")
	if err != nil {
		return nil, err
	}
	if params != nil && strings.TrimSpace(params.WorkspaceID) != "" {
		workspace, err = s.resolveWorkspaceForUser(ctx, user, params.WorkspaceID)
		if err != nil {
			return nil, err
		}
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	tasks, err := listTasks(ctx, s.db, workspace.ID, limit)
	if err != nil {
		runErrors.Add(1)
		log.Printf("listTasks: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query runs").Err()
	}

	if params != nil {
		if owner := strings.TrimSpace(params.Owner); owner != "" {
			filtered := make([]TaskRecord, 0, len(tasks))
			for _, task := range tasks {
				if strings.EqualFold(task.CreatedBy, owner) {
					filtered = append(filtered, task)
				}
			}
			tasks = filtered
		}
	}

	runItems := make([]map[string]any, 0, len(tasks))
	for _, task := range tasks {
		run := taskToRunInfo(task)
		run["workspaceId"] = workspace.ID
		runItems = append(runItems, run)
	}
	tasksJSON, err := toJSONMapSlice(runItems)
	if err != nil {
		log.Printf("runs list encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode runs").Err()
	}
	_ = ctx
	return &RunsListResponse{
		User:  user.Username,
		Tasks: tasksJSON,
	}, nil
}

type RunsCreateResponse struct {
	WorkspaceID string  `json:"workspaceId"`
	Task        JSONMap `json:"task"`
	User        string  `json:"user"`
}

// CreateRun is a reserved endpoint for admin-triggered native tasks.
//
//encore:api auth method=POST path=/api/runs
func (s *Service) CreateRun(ctx context.Context, req *RunRequest) (*RunsCreateResponse, error) {
	runCreateRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !isAdminUser(s.cfg, user.Username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden (use workspace run endpoints)").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	workspaceKey := ""
	if req.WorkspaceID != nil {
		workspaceKey = *req.WorkspaceID
	}
	if workspaceKey == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("workspace_id is required").Err()
	}
	if _, err := s.resolveWorkspaceForUser(ctx, user, workspaceKey); err != nil {
		return nil, err
	}
	return nil, errs.B().Code(errs.Unimplemented).Msg("direct run creation is not supported in native mode").Err()
}

type RunsOutputParams struct {
	WorkspaceID string `query:"workspace_id" encore:"optional"`
}

type RunsOutputResponse struct {
	TaskID      int       `json:"task_id"`
	WorkspaceID string    `json:"workspaceId"`
	Output      []JSONMap `json:"output"`
	User        string    `json:"user"`
}

// GetRunOutput returns output for a specific native task.
//
//encore:api auth method=GET path=/api/runs/:id/output
func (s *Service) GetRunOutput(ctx context.Context, id int, params *RunsOutputParams) (*RunsOutputResponse, error) {
	runOutputRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid task id").Err()
	}
	workspaceKey := ""
	if params != nil {
		workspaceKey = strings.TrimSpace(params.WorkspaceID)
	}
	workspace, err := s.resolveWorkspaceForUser(ctx, user, workspaceKey)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	output, err := listTaskLogs(ctx, s.db, id, 2000)
	if err != nil {
		runErrors.Add(1)
		log.Printf("listTaskLogs: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to fetch task output").Err()
	}
	outputItems := make([]map[string]any, 0, len(output))
	for _, entry := range output {
		item := map[string]any{
			"output": entry.Output,
			"time":   entry.Time,
			"stream": entry.Stream,
		}
		outputItems = append(outputItems, item)
	}
	outputJSON, err := toJSONMapSlice(outputItems)
	if err != nil {
		log.Printf("run output encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode task output").Err()
	}
	_ = ctx
	return &RunsOutputResponse{
		TaskID:      id,
		WorkspaceID: workspace.ID,
		Output:      outputJSON,
		User:        user.Username,
	}, nil
}
