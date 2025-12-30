package skyforge

import (
	"context"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

type RunnerRunsParams struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Limit     string `query:"limit" encore:"optional"`
}

type NetlabRun struct {
	Task  JSONMap           `json:"task"`
	Labs  map[string]string `json:"labs"`
	Files map[string]string `json:"artifacts"`
	User  string            `json:"user"`
}

type NetlabRunsResponse struct {
	ProjectID int         `json:"project_id"`
	User      string      `json:"user"`
	Runs      []NetlabRun `json:"runs"`
}

// GetNetlabRuns returns recent Netlab runs for a project.
//
//encore:api auth method=GET path=/api/netlab/runs
func (s *Service) GetNetlabRuns(ctx context.Context, params *RunnerRunsParams) (*NetlabRunsResponse, error) {
	netlabRunsRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	projectID, limit, err := parseRunnerRunsParams(s.cfg, params)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSemaphoreProjectID(claims, projectID); err != nil {
		return nil, err
	}

	tasks, err := fetchSemaphoreTasks(s.cfg, projectID, limit)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query semaphore").Err()
	}

	runs := make([]NetlabRun, 0, limit)
	for _, task := range tasks {
		tplAlias, _ := task["tpl_alias"].(string)
		tplApp, _ := task["tpl_app"].(string)
		if !strings.HasPrefix(strings.ToLower(tplAlias), "netlab") && strings.ToLower(tplApp) != "netlab" {
			continue
		}
		taskID, ok := task["id"].(float64)
		if !ok || int(taskID) <= 0 {
			continue
		}
		output, err := cachedSemaphoreTaskOutput(s.cfg, projectID, int(taskID))
		if err != nil {
			continue
		}
		labs, artifacts := parseSkyforgeMarkers(output)
		taskJSON, err := toJSONMap(task)
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
		ProjectID: projectID,
		User:      user.Username,
		Runs:      runs,
	}, nil
}

func parseRunnerRunsParams(cfg Config, params *RunnerRunsParams) (int, int, error) {
	projectID := cfg.DefaultProject
	limit := 10
	if params != nil {
		if raw := strings.TrimSpace(params.ProjectID); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil || v <= 0 {
				return 0, 0, errs.B().Code(errs.InvalidArgument).Msg("invalid project_id").Err()
			}
			projectID = v
		}
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 25 {
				limit = v
			}
		}
	}
	if projectID == 0 {
		return 0, 0, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
	}
	return projectID, limit, nil
}
