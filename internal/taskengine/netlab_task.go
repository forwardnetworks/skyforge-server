package taskengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type netlabTaskSpec struct {
	Action        string            `json:"action,omitempty"`
	Server        string            `json:"server,omitempty"`
	Deployment    string            `json:"deployment,omitempty"`
	DeploymentID  string            `json:"deploymentId,omitempty"`
	UserScopeRoot string            `json:"userScopeRoot,omitempty"`
	UserScopeDir  string            `json:"userScopeDir,omitempty"`
	Cleanup       bool              `json:"cleanup,omitempty"`
	TopologyPath  string            `json:"topologyPath,omitempty"`
	TopologyURL   string            `json:"topologyUrl,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
}

type netlabRunSpec struct {
	TaskID        int
	UserScopeCtx  *userContext
	UserScopeSlug string
	Username      string
	Environment   map[string]string
	Action        string
	Deployment    string
	DeploymentID  string
	UserScopeRoot string
	UserScopeDir  string
	Cleanup       bool
	Server        NetlabServerConfig
	TopologyPath  string
	TopologyURL   string
}

func (e *Engine) dispatchNetlabTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn netlabTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	ws, err := e.loadUserScopeByKey(ctx, task.UserScopeID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &userContext{
		userScope: *ws,
		claims: SessionClaims{
			Username: username,
		},
	}

	serverRef := strings.TrimSpace(specIn.Server)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.userScope.NetlabServer)
	}
	server, err := e.resolveUserScopeNetlabServer(ctx, pc.userScope.ID, serverRef)
	if err != nil {
		return err
	}

	runSpec := netlabRunSpec{
		TaskID:        task.ID,
		UserScopeCtx:  pc,
		UserScopeSlug: strings.TrimSpace(pc.userScope.Slug),
		Username:      username,
		Environment:   specIn.Environment,
		Action:        strings.TrimSpace(specIn.Action),
		Deployment:    strings.TrimSpace(specIn.Deployment),
		DeploymentID:  strings.TrimSpace(specIn.DeploymentID),
		UserScopeRoot: strings.TrimSpace(specIn.UserScopeRoot),
		UserScopeDir:  strings.TrimSpace(specIn.UserScopeDir),
		Cleanup:       specIn.Cleanup,
		Server:        *server,
		TopologyPath:  strings.TrimSpace(specIn.TopologyPath),
		TopologyURL:   strings.TrimSpace(specIn.TopologyURL),
	}

	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "netlab."+action, func() error {
		return e.runNetlabTask(ctx, runSpec, log)
	})
}

func (e *Engine) runNetlabTask(ctx context.Context, spec netlabRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.UserScopeCtx == nil {
		return fmt.Errorf("user context unavailable")
	}

	apiURL := netlabAPIURL(spec.Server)
	if apiURL == "" {
		return fmt.Errorf("netlab api url is not configured")
	}
	insecure := spec.Server.APIInsecure
	auth, err := e.netlabAPIAuthForUser(spec.Username, spec.Server)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"action":        strings.TrimSpace(spec.Action),
		"workdir":       strings.TrimSpace(spec.UserScopeDir),
		"userScopeRoot": strings.TrimSpace(spec.UserScopeRoot),
	}
	if strings.TrimSpace(spec.TopologyPath) != "" {
		payload["topologyPath"] = strings.TrimSpace(spec.TopologyPath)
	}
	if strings.TrimSpace(spec.TopologyURL) != "" {
		payload["topologyUrl"] = strings.TrimSpace(spec.TopologyURL)
	}
	if spec.Cleanup {
		payload["cleanup"] = true
	}

	log.Infof("Starting netlab job (%s)", strings.TrimSpace(spec.Action))
	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, body, err := netlabAPIDo(ctxReq, apiURL+"/jobs", payload, insecure, auth)
	if err != nil {
		return fmt.Errorf("failed to reach netlab API: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("netlab API rejected request: %s", strings.TrimSpace(string(body)))
	}
	var job netlabAPIJob
	if err := json.Unmarshal(body, &job); err != nil || strings.TrimSpace(job.ID) == "" {
		return fmt.Errorf("netlab API returned invalid response")
	}

	if spec.TaskID > 0 {
		metaAny := map[string]any{"netlabJobId": job.ID}
		metaJSON, err := toJSONMap(metaAny)
		if err == nil {
			metaCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = taskstore.UpdateTaskMetadata(metaCtx, e.db, spec.TaskID, metaJSON)
			cancel()
		}
	}

	lastLog := ""
	deadline := time.Now().Add(30 * time.Minute)
	for {
		if spec.TaskID > 0 {
			canceled, _ := e.taskCanceled(ctx, spec.TaskID)
			if canceled {
				_ = e.cancelNetlabJob(ctx, apiURL, job.ID, insecure, auth, log)
				return fmt.Errorf("netlab job canceled")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("netlab job timed out")
		}

		getResp, getBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s", apiURL, job.ID), insecure, auth)
		if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
			_ = json.Unmarshal(getBody, &job)
		}
		logResp, logBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s/log", apiURL, job.ID), insecure, auth)
		if err == nil && logResp != nil && logResp.StatusCode >= 200 && logResp.StatusCode < 300 {
			var lr netlabAPILog
			if err := json.Unmarshal(logBody, &lr); err == nil {
				if lr.Log != "" && lr.Log != lastLog {
					diff := lr.Log[len(lastLog):]
					if diff != "" {
						log.Infof("%s", diff)
					}
					lastLog = lr.Log
				}
			}
		}

		state := strings.ToLower(strings.TrimSpace(job.State))
		if state == "" {
			state = strings.ToLower(strings.TrimSpace(derefString(job.Status)))
		}
		if state == "success" || state == "failed" || state == "canceled" {
			if state != "success" {
				errText := strings.TrimSpace(derefString(job.Error))
				if isNetlabBenignFailure(spec.Action, errText, lastLog) {
					log.Infof("Netlab action treated as success: %s", errText)
					return nil
				}
				if errText != "" {
					return errors.New(errText)
				}
				return fmt.Errorf("netlab job %s", state)
			}
			// Best-effort artifact capture for later inspection.
			if spec.TaskID > 0 && spec.UserScopeCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" {
				_ = e.maybeUploadNetlabArtifacts(ctx, spec, apiURL, job.ID, insecure, auth, log)
			}
			// Best-effort Forward sync after successful runs (implemented separately).
			if strings.EqualFold(spec.Action, "up") || strings.EqualFold(spec.Action, "restart") || strings.EqualFold(spec.Action, "create") {
				_ = e.maybeSyncForwardNetlabAfterRun(ctx, spec, log, apiURL)
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

func (e *Engine) maybeUploadNetlabArtifacts(ctx context.Context, spec netlabRunSpec, apiURL, jobID string, insecure bool, auth netlabAPIAuth, log Logger) error {
	if e == nil || strings.TrimSpace(apiURL) == "" || strings.TrimSpace(jobID) == "" {
		return nil
	}
	if spec.UserScopeCtx == nil {
		return nil
	}
	wsID := strings.TrimSpace(spec.UserScopeCtx.userScope.ID)
	depID := strings.TrimSpace(spec.DeploymentID)
	if wsID == "" || depID == "" {
		return nil
	}

	type item struct {
		path        string
		keySuffix   string
		contentType string
		metaKey     string
		maxBytes    int
	}
	items := []item{
		{path: "netlab.snapshot.yml", keySuffix: "netlab.snapshot.yml", contentType: "application/yaml", metaKey: "netlabSnapshotKey", maxBytes: 4 << 20},
		{path: "clab.yml", keySuffix: "clab.yml", contentType: "application/yaml", metaKey: "netlabClabKey", maxBytes: 4 << 20},
	}

	for _, it := range items {
		ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
		data, err := netlabAPIGetJobArtifact(ctxReq, apiURL, jobID, it.path, insecure, auth)
		cancel()
		if err != nil || len(data) == 0 {
			continue
		}
		if it.maxBytes > 0 && len(data) > it.maxBytes {
			continue
		}
		key := fmt.Sprintf("netlab/%s/%s", depID, it.keySuffix)
		ctxPut, cancel := context.WithTimeout(ctx, 10*time.Second)
		putKey, err := putUserScopeArtifact(ctxPut, e.cfg, wsID, key, data, it.contentType)
		cancel()
		if err != nil {
			continue
		}
		e.setTaskMetadataKey(spec.TaskID, it.metaKey, putKey)
		if log != nil {
			log.Infof("Netlab artifact uploaded: %s", putKey)
		}
	}

	return nil
}

func (e *Engine) taskCanceled(ctx context.Context, taskID int) (bool, map[string]any) {
	if taskID <= 0 || e == nil || e.db == nil {
		return false, nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := taskstore.GetTask(ctxReq, e.db, taskID)
	if err != nil || rec == nil {
		return false, nil
	}
	if strings.EqualFold(strings.TrimSpace(rec.Status), "canceled") {
		return true, nil
	}
	return false, nil
}

func (e *Engine) cancelNetlabJob(ctx context.Context, apiURL, jobID string, insecure bool, auth netlabAPIAuth, log Logger) error {
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	jobID = strings.TrimSpace(jobID)
	if apiURL == "" || jobID == "" {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, body, err := netlabAPIDo(ctxReq, fmt.Sprintf("%s/jobs/%s/cancel", apiURL, jobID), map[string]any{}, insecure, auth)
	if err != nil {
		log.Infof("Netlab cancel request failed: %v", err)
		return err
	}
	_ = body
	return nil
}

func isNetlabBenignFailure(action string, errText string, logs string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	errText = strings.ToLower(strings.TrimSpace(errText))
	logs = strings.ToLower(strings.TrimSpace(logs))
	if action == "" {
		return false
	}
	if action == "down" || action == "destroy" || action == "delete" || action == "stop" {
		if strings.Contains(errText, "not found") || strings.Contains(logs, "not found") {
			return true
		}
	}
	return false
}
