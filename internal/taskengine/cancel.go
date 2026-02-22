package taskengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskstore"
)

func (e *Engine) CancelTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) {
	if e == nil || task == nil {
		return
	}
	if log == nil {
		log = noopLogger{}
	}
	typ := strings.ToLower(strings.TrimSpace(task.TaskType))
	if e.db != nil && task.ID > 0 && !strings.EqualFold(strings.TrimSpace(task.Status), "canceled") {
		_ = taskstore.AppendTaskEvent(context.Background(), e.db, task.ID, "cancel.requested", map[string]any{
			"taskType": typ,
		})
	}
	switch {
	case strings.HasPrefix(typ, "netlab"):
		e.cancelNetlabTask(ctx, task, log)
	}
	e.markCancelApplied(task.ID, typ)
}

func (e *Engine) cancelNetlabTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) {
	if e == nil || task == nil || log == nil {
		return
	}
	metaAny, _ := fromJSONMap(task.Metadata)
	jobID := strings.TrimSpace(fmt.Sprintf("%v", metaAny["netlabJobId"]))
	if jobID == "" {
		return
	}

	ws, err := e.loadWorkspaceByKey(ctx, task.WorkspaceID)
	if err != nil || ws == nil {
		return
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &userContext{
		workspace: *ws,
		claims: SessionClaims{
			Username: username,
		},
	}

	serverRef := ""
	switch strings.ToLower(strings.TrimSpace(task.TaskType)) {
	case "netlab-c9s-run":
		var spec netlabC9sTaskSpec
		if err := decodeTaskSpec(task, &spec); err == nil {
			serverRef = strings.TrimSpace(spec.Server)
		}
	default:
		var spec netlabTaskSpec
		if err := decodeTaskSpec(task, &spec); err == nil {
			serverRef = strings.TrimSpace(spec.Server)
		}
	}
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	server, err := e.resolveWorkspaceNetlabServer(ctx, pc.workspace.ID, serverRef)
	if err != nil || server == nil {
		return
	}
	apiURL := netlabAPIURL(*server)
	if apiURL == "" {
		return
	}
	auth, err := e.netlabAPIAuthForUser(username, *server)
	if err != nil {
		return
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for attempt := 1; attempt <= 3; attempt++ {
		if err := e.cancelNetlabJob(ctxReq, apiURL, jobID, server.APIInsecure, auth, log); err == nil {
			break
		}
		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}
}

func (e *Engine) markCancelApplied(taskID int, taskType string) {
	if e == nil || e.db == nil || taskID <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	task, err := taskstore.GetTask(ctx, e.db, taskID)
	if err != nil || task == nil {
		return
	}
	metaAny, _ := fromJSONMap(task.Metadata)
	if metaAny == nil {
		metaAny = map[string]any{}
	}
	if existing, ok := metaAny["cancelAppliedAt"]; ok && strings.TrimSpace(fmt.Sprintf("%v", existing)) != "" {
		return
	}
	metaAny["cancelAppliedAt"] = time.Now().UTC().Format(time.RFC3339)
	metaAny["cancelApplied"] = true
	if metaJSON, err := toJSONMap(metaAny); err == nil {
		_ = taskstore.UpdateTaskMetadata(ctx, e.db, taskID, metaJSON)
	}
	_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "cancel.applied", map[string]any{
		"taskType": strings.TrimSpace(taskType),
	})
}
