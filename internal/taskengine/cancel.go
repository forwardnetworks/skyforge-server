package taskengine

import (
	"context"
	"fmt"
	"strconv"
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
	switch {
	case strings.HasPrefix(typ, "netlab"):
		e.cancelNetlabTask(ctx, task, log)
	case strings.HasPrefix(typ, "labpp"):
		e.cancelLabppTask(ctx, task, log)
	}
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
	pc := &workspaceContext{
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
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
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
	e.cancelNetlabJob(ctxReq, apiURL, jobID, server.APIInsecure, auth, log)
}

func (e *Engine) cancelLabppTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) {
	if e == nil || task == nil || log == nil {
		return
	}
	if task.ID <= 0 {
		return
	}
	name := sanitizeKubeName("labpp-" + strconv.Itoa(task.ID))
	ns := kubeNamespace()
	kubeDeleteJob(context.Background(), ns, name)
}
