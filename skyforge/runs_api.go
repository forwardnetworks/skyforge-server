package skyforge

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskqueue"
	"encore.dev/beta/errs"
)

type RunsListParams struct {
	Limit string `query:"limit" encore:"optional"`
	Owner string `query:"owner" encore:"optional"`
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

	userContext, err := s.resolveUserForUser(ctx, user, personalOwnerRouteKey)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	tasks, err := listTasks(ctx, s.db, userContext.ID, limit)
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
	Task JSONMap `json:"task"`
	User string  `json:"user"`
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
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden (use user run endpoints)").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	ownerKey := personalOwnerRouteKey
	if req.OwnerUsername != nil {
		ownerKey = strings.TrimSpace(*req.OwnerUsername)
		if ownerKey == "" {
			ownerKey = personalOwnerRouteKey
		}
	}
	if _, err := s.resolveUserForUser(ctx, user, ownerKey); err != nil {
		return nil, err
	}
	return nil, errs.B().Code(errs.Unimplemented).Msg("direct run creation is not supported in native mode").Err()
}

type RunsOutputParams struct{}

type RunsCancelResponse struct {
	TaskID int      `json:"task_id"`
	Status string   `json:"status"`
	Task   *JSONMap `json:"task,omitempty"`
	User   string   `json:"user"`
}

// CancelRun cancels a queued or running task.
//
//encore:api auth method=POST path=/api/runs/:id/cancel
func (s *Service) CancelRun(ctx context.Context, id int, params *RunsOutputParams) (*RunsCancelResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid task id").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	// Load task first to determine owner/deployment ownership.
	task, err := getTask(ctx, s.db, id)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("task not found").Err()
	}
	if task == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("task not found").Err()
	}

	// Enforce task ownership within current user's accessible owner context.
	pc, err := s.ownerContextForUser(user, task.OwnerID)
	if err != nil {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	// Viewers can see runs but shouldn't cancel them.
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	status := strings.ToLower(strings.TrimSpace(task.Status))
	switch status {
	case "queued", "running":
	default:
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("task is not cancelable").Err()
	}

	if err := cancelTask(ctx, s.db, task.ID); err != nil {
		log.Printf("cancelTask: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to cancel task").Err()
	}

	// Worker-owned: best-effort propagate cancellation to external runners.
	_, _ = taskqueue.CancelTopic.Publish(ctx, &taskqueue.TaskCancelEvent{TaskID: task.ID})

	// Notify + update deployment status for UI.
	if err := s.notifyTaskEvent(ctx, task, "canceled", ""); err != nil {
		log.Printf("cancel notify: %v", err)
	}
	if task.DeploymentID.Valid {
		finishedAt := time.Now().UTC()
		if err := s.updateDeploymentStatus(ctx, task.OwnerID, task.DeploymentID.String, "canceled", &finishedAt); err != nil {
			log.Printf("cancel deployment status: %v", err)
		}

		// Kick the next queued run for this deployment to avoid "stuck queued" after cancel.
		ownerID := strings.TrimSpace(task.OwnerID)
		deploymentID := strings.TrimSpace(task.DeploymentID.String)
		if ownerID != "" && deploymentID != "" {
			if nextID, err := getOldestQueuedDeploymentTaskID(ctx, s.db, ownerID, deploymentID); err == nil && nextID > 0 {
				ctxKick, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				s.enqueueTaskID(ctxKick, nextID, ownerID, deploymentID, 0)
				cancel()
			}
		}
	}

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		return &RunsCancelResponse{TaskID: task.ID, Status: "canceled", User: user.Username}, nil
	}
	return &RunsCancelResponse{TaskID: task.ID, Status: "canceled", Task: &taskJSON, User: user.Username}, nil
}

type RunsOutputResponse struct {
	TaskID int       `json:"task_id"`
	Output []JSONMap `json:"output"`
	User   string    `json:"user"`
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
	task, err := getTask(ctx, s.db, id)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("task not found").Err()
	}
	if task == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("task not found").Err()
	}
	if _, err := s.ownerContextForUser(user, task.OwnerID); err != nil {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
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
		TaskID: id,
		Output: outputJSON,
		User:   user.Username,
	}, nil
}
