package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

func startSemaphoreRun(ctx context.Context, cfg Config, db *sql.DB, claims *SessionClaims, req RunRequest) (map[string]any, error) {
	projectID := cfg.DefaultProject
	if req.ProjectID != nil {
		projectID = *req.ProjectID
	}
	if projectID == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project_id is required").Err()
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

	resp, body, err := semaphoreDo(cfg, http.MethodPost, fmt.Sprintf("/project/%d/tasks", projectID), payload)
	if err != nil {
		log.Printf("startSemaphoreRun semaphoreDo: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp.StatusCode >= 400 {
		log.Printf("startSemaphoreRun semaphore response %d", resp.StatusCode)
		return nil, errs.B().Code(errs.Unavailable).Msg("semaphore rejected request").Err()
	}
	var task map[string]any
	if err := json.Unmarshal(body, &task); err != nil {
		log.Printf("startSemaphoreRun decode: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode semaphore response").Err()
	}
	if db != nil && claims != nil {
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
		if _, err := createNotification(ctx, db, claims.Username, title, message, "TASK_ASSIGNED", "runs", taskID, "medium"); err != nil {
			log.Printf("create notification (run): %v", err)
		}
	}
	return task, nil
}
