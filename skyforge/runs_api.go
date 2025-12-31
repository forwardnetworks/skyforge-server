package skyforge

import (
	"context"
	"log"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

type RunsListParams struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Limit     string `query:"limit" encore:"optional"`
	Owner     string `query:"owner" encore:"optional"`
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

	project, err := s.resolveProjectForUser(ctx, user, "")
	if err != nil {
		return nil, err
	}
	if params != nil && strings.TrimSpace(params.ProjectID) != "" {
		project, err = s.resolveProjectForUser(ctx, user, params.ProjectID)
		if err != nil {
			return nil, err
		}
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	tasks, err := listTasks(ctx, s.db, project.ID, limit)
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
		run["projectId"] = project.ID
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
	ProjectID string  `json:"projectId"`
	Task      JSONMap `json:"task"`
	User      string  `json:"user"`
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
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden (use project run endpoints)").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	projectKey := ""
	if req.ProjectID != nil {
		projectKey = *req.ProjectID
	}
	if projectKey == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}
	if _, err := s.resolveProjectForUser(ctx, user, projectKey); err != nil {
		return nil, err
	}
	return nil, errs.B().Code(errs.Unimplemented).Msg("direct run creation is not supported in native mode").Err()
}

type RunsOutputParams struct {
	ProjectID string `query:"project_id" encore:"optional"`
}

type RunsOutputResponse struct {
	TaskID    int       `json:"task_id"`
	ProjectID string    `json:"projectId"`
	Output    []JSONMap `json:"output"`
	User      string    `json:"user"`
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
	projectKey := ""
	if params != nil {
		projectKey = strings.TrimSpace(params.ProjectID)
	}
	project, err := s.resolveProjectForUser(ctx, user, projectKey)
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
		TaskID:    id,
		ProjectID: project.ID,
		Output:    outputJSON,
		User:      user.Username,
	}, nil
}
