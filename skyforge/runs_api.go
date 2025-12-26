package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// GetRuns returns recent runs from Semaphore.
//
//encore:api auth method=GET path=/api/runs tag:list-runs
func (s *Service) GetRuns(ctx context.Context, params *RunsListParams) (*RunsListResponse, error) {
	runListRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	projectID := s.cfg.DefaultProject
	if params != nil && strings.TrimSpace(params.ProjectID) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(params.ProjectID)); err == nil {
			projectID = v
		} else {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid project_id").Err()
		}
	}
	if projectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}
	if err := s.authorizeSemaphoreProjectID(claims, projectID); err != nil {
		return nil, err
	}
	limit := 5
	if params != nil && strings.TrimSpace(params.Limit) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(params.Limit)); err == nil && v > 0 {
			limit = v
		}
	}

	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, claims.Username)
	if err != nil {
		return nil, err
	}
	tasks, err := fetchSemaphoreTasks(semaphoreCfg, projectID, limit)
	if err != nil {
		runErrors.Add(1)
		log.Printf("fetchSemaphoreTasks: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query semaphore").Err()
	}

	if params != nil {
		if owner := strings.TrimSpace(params.Owner); owner != "" {
			filtered := make([]map[string]any, 0, len(tasks))
			for _, task := range tasks {
				if username, ok := task["user_name"].(string); ok && strings.EqualFold(username, owner) {
					filtered = append(filtered, task)
				}
			}
			tasks = filtered
		}
	}

	tasksJSON, err := toJSONMapSlice(tasks)
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

// GetRunsV1 returns recent runs from Semaphore (v1 alias).
//
//encore:api auth method=GET path=/api/v1/runs tag:list-runs
func (s *Service) GetRunsV1(ctx context.Context, params *RunsListParams) (*RunsListResponse, error) {
	return s.GetRuns(ctx, params)
}

type RunsCreateResponse struct {
	ProjectID int     `json:"project_id"`
	Task      JSONMap `json:"task"`
	User      string  `json:"user"`
}

// CreateRun launches a task in Semaphore (admin only).
//
//encore:api auth method=POST path=/api/runs
func (s *Service) CreateRun(ctx context.Context, req *RunRequest) (*RunsCreateResponse, error) {
	runCreateRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	if !isAdminUser(s.cfg, user.Username) {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden (use project run endpoints)").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	projectID := s.cfg.DefaultProject
	if req.ProjectID != nil {
		projectID = *req.ProjectID
	}
	if projectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}
	if err := s.authorizeSemaphoreProjectID(claims, projectID); err != nil {
		return nil, err
	}
	if req.TemplateID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templateId is required").Err()
	}

	payload := map[string]any{
		"template_id": req.TemplateID,
		"debug":       req.Debug,
		"dry_run":     req.DryRun,
		"diff":        req.Diff,
	}
	if req.Playbook != "" {
		payload["playbook"] = req.Playbook
	}
	if req.Environment != nil {
		envBytes, err := json.Marshal(req.Environment)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("failed to encode environment").Err()
		}
		payload["environment"] = string(envBytes)
	}
	if req.Limit != "" {
		payload["limit"] = req.Limit
	}
	if req.GitBranch != "" {
		payload["git_branch"] = req.GitBranch
	}
	if req.Message != "" {
		payload["message"] = req.Message
	}
	if strings.TrimSpace(req.Arguments) != "" {
		payload["arguments"] = req.Arguments
	}
	if req.InventoryID != nil {
		payload["inventory_id"] = *req.InventoryID
	}
	if req.Extra != nil {
		for k, v := range req.Extra {
			payload[k] = v
		}
	}

	resp, body, err := semaphoreDo(s.cfg, http.MethodPost, fmt.Sprintf("/project/%d/tasks", projectID), payload)
	if err != nil {
		runErrors.Add(1)
		log.Printf("create run semaphoreDo: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp.StatusCode >= 400 {
		runErrors.Add(1)
		log.Printf("create run semaphore response %d", resp.StatusCode)
		return nil, errs.B().Code(errs.Unavailable).Msg("semaphore rejected request").Err()
	}
	var task map[string]any
	if err := json.Unmarshal(body, &task); err != nil {
		log.Printf("create run decode: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode semaphore response").Err()
	}
	if s.db != nil {
		taskID := ""
		switch v := task["id"].(type) {
		case float64:
			if int(v) > 0 {
				taskID = strconv.Itoa(int(v))
			}
		case int:
			if v > 0 {
				taskID = strconv.Itoa(v)
			}
		case string:
			taskID = strings.TrimSpace(v)
		}
		title := "Run started"
		message := fmt.Sprintf("Semaphore task %s started for project %d.", taskID, projectID)
		if taskID == "" {
			message = fmt.Sprintf("Semaphore task started for project %d.", projectID)
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if _, err := createNotification(ctx, s.db, user.Username, title, message, "TASK_ASSIGNED", "runs", taskID, "medium"); err != nil {
			log.Printf("create notification (run): %v", err)
		}
	}
	taskJSON, err := toJSONMap(task)
	if err != nil {
		log.Printf("create run encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &RunsCreateResponse{
		ProjectID: projectID,
		Task:      taskJSON,
		User:      user.Username,
	}, nil
}

// CreateRunV1 launches a task in Semaphore (v1 alias).
//
//encore:api auth method=POST path=/api/v1/runs
func (s *Service) CreateRunV1(ctx context.Context, req *RunRequest) (*RunsCreateResponse, error) {
	return s.CreateRun(ctx, req)
}

type RunsOutputParams struct {
	ProjectID string `query:"project_id" encore:"optional"`
}

type RunsOutputResponse struct {
	TaskID    int       `json:"task_id"`
	ProjectID int       `json:"project_id"`
	Output    []JSONMap `json:"output"`
	User      string    `json:"user"`
}

// GetRunOutput returns output for a specific Semaphore task.
//
//encore:api auth method=GET path=/api/runs/:id/output
func (s *Service) GetRunOutput(ctx context.Context, id int, params *RunsOutputParams) (*RunsOutputResponse, error) {
	runOutputRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	if id <= 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid task id").Err()
	}
	projectID := s.cfg.DefaultProject
	if params != nil && strings.TrimSpace(params.ProjectID) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(params.ProjectID)); err == nil {
			projectID = v
		} else {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid project_id").Err()
		}
	}
	if projectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}
	if err := s.authorizeSemaphoreProjectID(claims, projectID); err != nil {
		return nil, err
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, claims.Username)
	if err != nil {
		return nil, err
	}
	payload, err := cachedSemaphoreTaskOutput(semaphoreCfg, projectID, id)
	if err != nil {
		runErrors.Add(1)
		log.Printf("fetchSemaphoreTaskOutput: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to fetch task output").Err()
	}
	outputJSON, err := toJSONMapSlice(payload)
	if err != nil {
		log.Printf("run output encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode task output").Err()
	}
	_ = ctx
	return &RunsOutputResponse{
		TaskID:    id,
		ProjectID: projectID,
		Output:    outputJSON,
		User:      user.Username,
	}, nil
}

// GetRunOutputV1 returns output for a specific Semaphore task (v1 alias).
//
//encore:api auth method=GET path=/api/v1/runs/:id/output
func (s *Service) GetRunOutputV1(ctx context.Context, id int, params *RunsOutputParams) (*RunsOutputResponse, error) {
	return s.GetRunOutput(ctx, id, params)
}
