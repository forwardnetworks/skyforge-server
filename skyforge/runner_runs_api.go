package skyforge

import (
	"context"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

type RunnerRunsParams struct {
	Limit string `query:"limit" encore:"optional"`
}

type NetlabRun struct {
	Task  JSONMap           `json:"task"`
	Labs  map[string]string `json:"labs"`
	Files map[string]string `json:"artifacts"`
	User  string            `json:"user"`
}

type NetlabRunsResponse struct {
	UserContextID string      `json:"userContextId"`
	User          string      `json:"user"`
	Runs          []NetlabRun `json:"runs"`
}

// GetNetlabRuns returns recent Netlab runs for the caller's default user context.
//
//encore:api auth method=GET path=/api/netlab/runs
func (s *Service) GetNetlabRuns(ctx context.Context, params *RunnerRunsParams) (*NetlabRunsResponse, error) {
	netlabRunsRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	limit, err := parseRunnerRunsParams(params)
	if err != nil {
		return nil, err
	}
	userContext, err := s.resolveUserContextForUser(ctx, user, "")
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	tasks, err := listTasks(ctx, s.db, userContext.ID, limit)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query runs").Err()
	}

	runs := make([]NetlabRun, 0, limit)
	for _, task := range tasks {
		if !strings.HasPrefix(strings.ToLower(task.TaskType), "netlab") {
			continue
		}
		output, err := listTaskLogs(ctx, s.db, task.ID, 2000)
		if err != nil {
			continue
		}
		logRows := make([]map[string]any, 0, len(output))
		for _, row := range output {
			logRows = append(logRows, map[string]any{"output": row.Output})
		}
		labs, artifacts := parseSkyforgeMarkers(logRows)
		runInfo := taskToRunInfo(task)
		runInfo["userContextId"] = userContext.ID
		taskJSON, err := toJSONMap(runInfo)
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode task").Err()
		}
		runs = append(runs, NetlabRun{
			Task:  taskJSON,
			Labs:  labs,
			Files: artifacts,
			User:  user.Username,
		})
	}

	_ = ctx
	return &NetlabRunsResponse{
		UserContextID: userContext.ID,
		User:          user.Username,
		Runs:          runs,
	}, nil
}

func parseRunnerRunsParams(params *RunnerRunsParams) (int, error) {
	limit := 10
	if params != nil {
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 25 {
				limit = v
			}
		}
	}
	return limit, nil
}
