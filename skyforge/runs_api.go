package skyforge

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

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

type RunsCancelResponse struct {
	TaskID      int      `json:"task_id"`
	WorkspaceID string   `json:"workspaceId"`
	Status      string   `json:"status"`
	Task        *JSONMap `json:"task,omitempty"`
	User        string   `json:"user"`
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

	// Load task first to determine workspace/deployment ownership.
	task, err := getTask(ctx, s.db, id)
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("task not found").Err()
	}
	if task == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("task not found").Err()
	}

	// Resolve workspace access (also enforces user membership).
	workspaceKey := ""
	if params != nil {
		workspaceKey = strings.TrimSpace(params.WorkspaceID)
	}
	workspace, err := s.resolveWorkspaceForUser(ctx, user, workspaceKey)
	if err != nil {
		return nil, err
	}
	if workspace.ID != task.WorkspaceID {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	// Viewers can see runs but shouldn't cancel them.
	pc, err := s.workspaceContextForUser(user, workspace.ID)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}

	status := strings.ToLower(strings.TrimSpace(task.Status))
	switch status {
	case "queued", "running":
	default:
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("task is not cancelable").Err()
	}

	// Best-effort: propagate cancel for known cancellable task types.
	meta, _ := fromJSONMap(task.Metadata)
	taskType := strings.ToLower(strings.TrimSpace(task.TaskType))
	if strings.HasPrefix(taskType, "netlab") {
		jobID := strings.TrimSpace(labppMetaString(meta, "netlabJobId"))
		if jobID != "" {
			serverName := strings.TrimSpace(labppMetaString(meta, "server"))
			if serverName == "" {
				var spec netlabTaskSpec
				if err := decodeTaskSpec(task, &spec); err == nil {
					serverName = strings.TrimSpace(spec.Server)
				} else {
					var specC9s netlabC9sTaskSpec
					if err := decodeTaskSpec(task, &specC9s); err == nil {
						serverName = strings.TrimSpace(specC9s.Server)
					}
				}
			}
			var server *NetlabServerConfig
			if serverID, ok := parseWorkspaceServerRef(serverName); ok {
				if s.db != nil {
					rec, err := getWorkspaceNetlabServerByID(ctx, s.db, s.box, workspace.ID, serverID)
					if err == nil && rec != nil {
						custom := NetlabServerConfig{
							Name:        strings.TrimSpace(rec.Name),
							APIURL:      strings.TrimSpace(rec.APIURL),
							APIInsecure: rec.APIInsecure,
							APIToken:    strings.TrimSpace(rec.APIToken),
							StateRoot:   strings.TrimSpace(s.cfg.Netlab.StateRoot),
						}
						custom = normalizeNetlabServer(custom, s.cfg.Netlab)
						server = &custom
					}
				}
			} else {
				srv, _ := resolveNetlabServer(s.cfg, serverName)
				server = srv
			}
			if server != nil {
				apiURL := strings.TrimSpace(server.APIURL)
				if apiURL == "" && strings.TrimSpace(server.SSHHost) != "" {
					apiURL = strings.TrimRight("https://"+strings.TrimSpace(server.SSHHost)+"/netlab", "/")
				}
				if apiURL != "" {
					log := &taskLogger{svc: s, taskID: task.ID}
					auth, err := s.netlabAPIAuthForUser(user.Username, *server)
					if err == nil {
						s.cancelNetlabJob(ctx, apiURL, jobID, server.APIInsecure, auth, log)
					}
				}
			}
		}
	}
	if strings.HasPrefix(taskType, "labpp") {
		// LabPP runs as an in-cluster Job named labpp-<taskId>.
		kubeDeleteJob(context.Background(), kubeNamespace(), sanitizeKubeName("labpp-"+strconv.Itoa(task.ID)))
	}
	if strings.HasPrefix(taskType, "containerlab") {
		// Containerlab tasks poll for cancellation; marking canceled is sufficient.
	}
	if strings.HasPrefix(taskType, "clabernetes") {
		// Clabernetes tasks poll for cancellation; marking canceled is sufficient.
	}
	if strings.HasPrefix(taskType, "terraform") {
		// Terraform tasks poll for cancellation; marking canceled is sufficient.
	}

	if err := cancelTask(ctx, s.db, task.ID); err != nil {
		log.Printf("cancelTask: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to cancel task").Err()
	}

	// Notify + update deployment status for UI.
	if err := s.notifyTaskEvent(ctx, task, "canceled", ""); err != nil {
		log.Printf("cancel notify: %v", err)
	}
	if task.DeploymentID.Valid {
		finishedAt := time.Now().UTC()
		if err := s.updateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, "canceled", &finishedAt); err != nil {
			log.Printf("cancel deployment status: %v", err)
		}

		// Kick the next queued run for this deployment to avoid "stuck queued" after cancel.
		workspaceID := strings.TrimSpace(task.WorkspaceID)
		deploymentID := strings.TrimSpace(task.DeploymentID.String)
		if workspaceID != "" && deploymentID != "" {
			if nextID, err := getOldestQueuedDeploymentTaskID(ctx, s.db, workspaceID, deploymentID); err == nil && nextID > 0 {
				ctxKick, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				s.enqueueTaskID(ctxKick, nextID, workspaceID, deploymentID, 0)
				cancel()
			}
		}
	}

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		return &RunsCancelResponse{TaskID: task.ID, WorkspaceID: workspace.ID, Status: "canceled", User: user.Username}, nil
	}
	return &RunsCancelResponse{TaskID: task.ID, WorkspaceID: workspace.ID, Status: "canceled", Task: &taskJSON, User: user.Username}, nil
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
