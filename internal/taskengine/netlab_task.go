package taskengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type netlabTaskSpec struct {
	Action          string            `json:"action,omitempty"`
	Server          string            `json:"server,omitempty"`
	Deployment      string            `json:"deployment,omitempty"`
	DeploymentID    string            `json:"deploymentId,omitempty"`
	WorkspaceRoot   string            `json:"workspaceRoot,omitempty"`
	TemplateSource  string            `json:"templateSource,omitempty"`
	TemplateRepo    string            `json:"templateRepo,omitempty"`
	TemplatesDir    string            `json:"templatesDir,omitempty"`
	Template        string            `json:"template,omitempty"`
	WorkspaceDir    string            `json:"workspaceDir,omitempty"`
	MultilabNumeric int               `json:"multilabNumeric,omitempty"`
	Cleanup         bool              `json:"cleanup,omitempty"`
	TopologyPath    string            `json:"topologyPath,omitempty"`
	ClabTarball     string            `json:"clabTarball,omitempty"`
	ClabConfigDir   string            `json:"clabConfigDir,omitempty"`
	ClabCleanup     bool              `json:"clabCleanup,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
}

type netlabRunSpec struct {
	TaskID          int
	WorkspaceCtx    *workspaceContext
	WorkspaceSlug   string
	Username        string
	Environment     map[string]string
	Action          string
	Deployment      string
	DeploymentID    string
	WorkspaceRoot   string
	TemplateSource  string
	TemplateRepo    string
	TemplatesDir    string
	Template        string
	WorkspaceDir    string
	MultilabNumeric int
	StateRoot       string
	Cleanup         bool
	Server          NetlabServerConfig
	TopologyPath    string
	ClabTarball     string
	ClabConfigDir   string
	ClabCleanup     bool
}

func (e *Engine) dispatchNetlabTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn netlabTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	ws, err := e.loadWorkspaceByKey(ctx, task.WorkspaceID)
	if err != nil {
		return err
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

	serverRef := strings.TrimSpace(specIn.Server)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if serverRef == "" {
		// backward-compat fallback (historically overloaded field)
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := e.resolveWorkspaceNetlabServer(ctx, pc.workspace.ID, serverRef)
	if err != nil {
		return err
	}

	if strings.TrimSpace(specIn.TemplateSource) == "" {
		specIn.TemplateSource = "blueprints"
	}

	runSpec := netlabRunSpec{
		TaskID:          task.ID,
		WorkspaceCtx:    pc,
		WorkspaceSlug:   strings.TrimSpace(pc.workspace.Slug),
		Username:        username,
		Environment:     specIn.Environment,
		Action:          strings.TrimSpace(specIn.Action),
		Deployment:      strings.TrimSpace(specIn.Deployment),
		DeploymentID:    strings.TrimSpace(specIn.DeploymentID),
		WorkspaceRoot:   strings.TrimSpace(specIn.WorkspaceRoot),
		TemplateSource:  strings.TrimSpace(specIn.TemplateSource),
		TemplateRepo:    strings.TrimSpace(specIn.TemplateRepo),
		TemplatesDir:    strings.TrimSpace(specIn.TemplatesDir),
		Template:        strings.TrimSpace(specIn.Template),
		WorkspaceDir:    strings.TrimSpace(specIn.WorkspaceDir),
		MultilabNumeric: specIn.MultilabNumeric,
		StateRoot:       strings.TrimSpace(server.StateRoot),
		Cleanup:         specIn.Cleanup,
		Server:          *server,
		TopologyPath:    strings.TrimSpace(specIn.TopologyPath),
		ClabTarball:     strings.TrimSpace(specIn.ClabTarball),
		ClabConfigDir:   strings.TrimSpace(specIn.ClabConfigDir),
		ClabCleanup:     specIn.ClabCleanup,
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
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}

	// If a template was selected, bundle it from the repo and let the netlab API server
	// extract it into the workdir before running netlab.
	topologyBundleB64 := ""
	if strings.TrimSpace(spec.Template) != "" {
		log.Infof("Preparing netlab template bundle %s", strings.TrimSpace(spec.Template))
		b64, err := e.buildNetlabTopologyBundleB64(ctx, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template)
		if err != nil {
			return err
		}
		topologyBundleB64 = strings.TrimSpace(b64)
		// When a bundle is present, the netlab API server writes the selected topology to workdir/topology.yml.
		if strings.TrimSpace(spec.TopologyPath) == "" {
			spec.TopologyPath = "topology.yml"
		}
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
		"user":          strings.TrimSpace(spec.Username),
		"workspace":     strings.TrimSpace(spec.WorkspaceSlug),
		"deployment":    strings.TrimSpace(spec.Deployment),
		"workspaceRoot": strings.TrimSpace(spec.WorkspaceRoot),
		"plugin":        "multilab",
		"multilabId":    strconv.Itoa(spec.MultilabNumeric),
		"instance":      strconv.Itoa(spec.MultilabNumeric),
		"stateRoot":     strings.TrimSpace(spec.StateRoot),
	}
	if strings.TrimSpace(spec.TopologyPath) != "" {
		payload["topologyPath"] = strings.TrimSpace(spec.TopologyPath)
	}
	if topologyBundleB64 != "" {
		payload["topologyBundleB64"] = topologyBundleB64
	}
	if strings.TrimSpace(spec.ClabTarball) != "" {
		payload["clabTarball"] = strings.TrimSpace(spec.ClabTarball)
	}
	if strings.TrimSpace(spec.ClabConfigDir) != "" {
		payload["clabConfigDir"] = strings.TrimSpace(spec.ClabConfigDir)
	}
	if spec.ClabCleanup {
		payload["clabCleanup"] = true
	}
	if spec.Cleanup {
		payload["cleanup"] = true
	}
	if len(spec.Environment) > 0 {
		payload["environment"] = spec.Environment
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
				e.cancelNetlabJob(ctx, apiURL, job.ID, insecure, auth, log)
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
			// Best-effort Forward sync after successful runs (implemented separately).
			if strings.EqualFold(spec.Action, "up") || strings.EqualFold(spec.Action, "restart") || strings.EqualFold(spec.Action, "create") {
				_ = e.maybeSyncForwardNetlabAfterRun(ctx, spec, log, apiURL)
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
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

func (e *Engine) cancelNetlabJob(ctx context.Context, apiURL, jobID string, insecure bool, auth netlabAPIAuth, log Logger) {
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	jobID = strings.TrimSpace(jobID)
	if apiURL == "" || jobID == "" {
		return
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, body, err := netlabAPIDo(ctxReq, fmt.Sprintf("%s/jobs/%s/cancel", apiURL, jobID), map[string]any{}, insecure, auth)
	if err != nil {
		log.Infof("Netlab cancel request failed: %v", err)
		return
	}
	_ = body
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
