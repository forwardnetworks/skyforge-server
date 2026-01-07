package skyforge

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"encore.app/storage"
)

type taskLogger struct {
	svc    *Service
	taskID int
}

func (l *taskLogger) Infof(format string, args ...any) {
	_ = appendTaskLog(context.Background(), l.svc.db, l.taskID, "stdout", fmt.Sprintf(format, args...))
}

func (l *taskLogger) Errorf(format string, args ...any) {
	_ = appendTaskLog(context.Background(), l.svc.db, l.taskID, "stderr", fmt.Sprintf(format, args...))
}

func (s *Service) taskCanceled(ctx context.Context, taskID int) (bool, map[string]any) {
	if taskID <= 0 || s.db == nil {
		return false, nil
	}
	rec, err := getTask(ctx, s.db, taskID)
	if err != nil || rec == nil {
		return false, nil
	}
	meta, _ := fromJSONMap(rec.Metadata)
	if strings.EqualFold(rec.Status, "canceled") {
		return true, meta
	}
	return false, meta
}

func labppMetaString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	raw, ok := meta[key]
	if !ok {
		return ""
	}
	if v, ok := raw.(string); ok {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}

func (s *Service) cancelLabppJob(ctx context.Context, apiURL, jobID string, insecure bool, log *taskLogger) {
	if strings.TrimSpace(jobID) == "" {
		return
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, body, err := labppAPICancel(ctxReq, fmt.Sprintf("%s/jobs/%s/cancel", strings.TrimRight(apiURL, "/"), jobID), insecure)
	if err != nil {
		log.Errorf("LabPP cancel failed: %v", err)
		return
	}
	if resp.StatusCode == http.StatusNotFound {
		log.Infof("LabPP cancel: job not found (treated as canceled).")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Errorf("LabPP cancel rejected: %s", strings.TrimSpace(string(body)))
		return
	}
	log.Infof("LabPP cancel requested for job %s", jobID)
}

func (s *Service) cancelNetlabJob(ctx context.Context, apiURL, jobID string, log *taskLogger) {
	if strings.TrimSpace(jobID) == "" {
		return
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, body, err := netlabAPIDo(ctxReq, fmt.Sprintf("%s/jobs/%s/cancel", strings.TrimRight(apiURL, "/"), jobID), nil)
	if err != nil {
		log.Errorf("Netlab cancel failed: %v", err)
		return
	}
	if resp.StatusCode == http.StatusNotFound {
		log.Infof("Netlab cancel: job not found (treated as canceled).")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Errorf("Netlab cancel rejected: %s", strings.TrimSpace(string(body)))
		return
	}
	log.Infof("Netlab cancel requested for job %s", jobID)
}

func (s *Service) queueTask(task *TaskRecord, runner func(ctx context.Context, log *taskLogger) error) {
	go func() {
		ctx := context.Background()
		if err := markTaskStarted(ctx, s.db, task.ID); err != nil {
			stdlog.Printf("task start update failed: %v", err)
		}
		logger := &taskLogger{svc: s, taskID: task.ID}
		err := runner(ctx, logger)
		status := "success"
		errMsg := ""
		if err != nil {
			status = "failed"
			errMsg = err.Error()
			logger.Errorf("ERROR: %s", errMsg)
		}
		if rec, recErr := getTask(ctx, s.db, task.ID); recErr == nil && rec != nil && strings.EqualFold(rec.Status, "canceled") {
			status = "canceled"
			errMsg = ""
		}
		if status != "canceled" {
			if err := finishTask(ctx, s.db, task.ID, status, errMsg); err != nil {
				stdlog.Printf("task finish update failed: %v", err)
			}
		}
		if task.DeploymentID.Valid {
			finishedAt := time.Now().UTC()
			if err := s.updateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, status, &finishedAt); err != nil {
				stdlog.Printf("deployment status update failed: %v", err)
			}
		}
	}()
}

type netlabRunSpec struct {
	TaskID          int
	WorkspaceCtx    *workspaceContext
	WorkspaceSlug   string
	Username        string
	Environment     map[string]string
	Action          string
	Deployment      string
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

func (s *Service) runNetlabTask(ctx context.Context, spec netlabRunSpec, log *taskLogger) error {
	if spec.Template != "" {
		log.Infof("Syncing netlab template %s", spec.Template)
		if spec.WorkspaceCtx == nil {
			return fmt.Errorf("workspace context unavailable")
		}
		topologyPath, err := s.syncNetlabTopologyFile(ctx, spec.WorkspaceCtx, &spec.Server, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template, spec.WorkspaceDir, spec.Username)
		if err != nil {
			return err
		}
		spec.TopologyPath = topologyPath
	}

	apiURL := strings.TrimRight(fmt.Sprintf("https://%s/netlab", strings.TrimSpace(spec.Server.SSHHost)), "/")
	payload := map[string]any{
		"action":        spec.Action,
		"user":          spec.Username,
		"workspace":     spec.WorkspaceSlug,
		"deployment":    spec.Deployment,
		"workspaceRoot": spec.WorkspaceRoot,
		"plugin":        "multilab",
		"multilabId":    strconv.Itoa(spec.MultilabNumeric),
		"instance":      strconv.Itoa(spec.MultilabNumeric),
		"stateRoot":     strings.TrimSpace(spec.StateRoot),
	}
	if strings.TrimSpace(spec.TopologyPath) != "" {
		payload["topologyPath"] = strings.TrimSpace(spec.TopologyPath)
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

	log.Infof("Starting netlab job (%s)", spec.Action)
	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, body, err := netlabAPIDo(ctxReq, apiURL+"/jobs", payload)
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
		if err != nil {
			stdlog.Printf("netlab metadata encode: %v", err)
		} else {
			metaCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := updateTaskMetadata(metaCtx, s.db, spec.TaskID, metaJSON); err != nil {
				stdlog.Printf("netlab metadata update: %v", err)
			}
			cancel()
		}
	}

	lastLog := ""
	deadline := time.Now().Add(30 * time.Minute)
	for {
		if spec.TaskID > 0 {
			canceled, _ := s.taskCanceled(ctx, spec.TaskID)
			if canceled {
				s.cancelNetlabJob(ctx, apiURL, job.ID, log)
				return fmt.Errorf("netlab job canceled")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("netlab job timed out")
		}

		getResp, getBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s", apiURL, job.ID))
		if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
			_ = json.Unmarshal(getBody, &job)
		}
		logResp, logBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s/log", apiURL, job.ID))
		if err == nil && logResp != nil && logResp.StatusCode >= 200 && logResp.StatusCode < 300 {
			var lr netlabAPILog
			if err := json.Unmarshal(logBody, &lr); err == nil {
				if lr.Log != "" && lr.Log != lastLog {
					diff := lr.Log[len(lastLog):]
					if diff != "" {
						log.Infof(diff)
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
				errText := ""
				if job.Error != nil {
					errText = strings.TrimSpace(*job.Error)
				}
				if isNetlabBenignFailure(spec.Action, errText, lastLog) {
					log.Infof("Netlab action treated as success: %s", errText)
					return nil
				}
				if errText != "" {
					return errors.New(errText)
				}
				return fmt.Errorf("netlab job %s", state)
			}
			if strings.EqualFold(spec.Action, "clab-tarball") {
				if err := s.publishNetlabClabTarball(ctx, spec, log); err != nil {
					return err
				}
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

func isNetlabBenignFailure(action string, errText string, logs string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "down" && action != "cleanup" {
		return false
	}
	candidate := strings.ToLower(strings.TrimSpace(errText))
	if candidate == "" {
		candidate = strings.ToLower(strings.TrimSpace(logs))
	}
	if candidate == "" {
		return false
	}
	for _, marker := range []string{
		"no netlab-managed labs",
		"lab is not started",
		"cannot display node/tool status",
	} {
		if strings.Contains(candidate, marker) {
			return true
		}
	}
	return false
}

func (s *Service) publishNetlabClabTarball(ctx context.Context, spec netlabRunSpec, log *taskLogger) error {
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	tarball := strings.TrimSpace(spec.ClabTarball)
	if tarball == "" {
		return nil
	}
	remotePath := tarball
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = path.Join(spec.WorkspaceDir, remotePath)
	}

	sshCfg := NetlabConfig{
		SSHHost:    strings.TrimSpace(spec.Server.SSHHost),
		SSHUser:    strings.TrimSpace(spec.Server.SSHUser),
		SSHKeyFile: strings.TrimSpace(spec.Server.SSHKeyFile),
		StateRoot:  "/",
	}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return err
	}
	defer client.Close()

	out, err := runSSHCommand(client, fmt.Sprintf("base64 %q", remotePath), 2*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to read clab tarball: %w", err)
	}
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		default:
			return r
		}
	}, out)
	payload, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return fmt.Errorf("failed to decode clab tarball: %w", err)
	}

	key := path.Join("netlab", spec.Deployment, path.Base(remotePath))
	objectName := artifactObjectName(spec.WorkspaceCtx.workspace.ID, key)
	if err := storage.Write(ctx, &storage.WriteRequest{ObjectName: objectName, Data: payload}); err != nil {
		return fmt.Errorf("failed to upload clab tarball: %w", err)
	}
	log.Infof("SKYFORGE_ARTIFACT clab_tarball=%s", key)
	return nil
}

type labppRunSpec struct {
	TaskID        int
	WorkspaceCtx  *workspaceContext
	DeploymentID  string
	APIURL        string
	Insecure      bool
	Action        string
	WorkspaceSlug string
	Username      string
	Deployment    string
	Environment   map[string]string
	TemplatesRoot string
	Template      string
	LabPath       string
	ThreadCount   int
	EveURL        string
	EveUsername   string
	EvePassword   string
	MaxSeconds    int
	Metadata      JSONMap
}

type labppJob struct {
	ID     string  `json:"id"`
	Status *string `json:"status,omitempty"`
	State  *string `json:"state,omitempty"`
	Error  *string `json:"error,omitempty"`
}

type labppLog struct {
	Log string `json:"log"`
}

func labppAPIDo(ctx context.Context, url string, payload any, insecure bool) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure && strings.HasPrefix(url, "https") {
		client.Transport = insecureTransport()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func labppAPIGet(ctx context.Context, url string, insecure bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure && strings.HasPrefix(url, "https") {
		client.Transport = insecureTransport()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func labppAPICancel(ctx context.Context, url string, insecure bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure && strings.HasPrefix(url, "https") {
		client.Transport = insecureTransport()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func normalizeLabppLog(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			if logVal, ok := parsed["log"].(string); ok {
				raw = logVal
			}
		}
	}
	raw = strings.ReplaceAll(raw, "Lab path: Users/", "Lab path: /Users/")
	if !strings.HasSuffix(raw, "\n") {
		raw += "\n"
	}
	return raw
}

func labppPayloadPreview(payload map[string]any) string {
	preview := map[string]any{}
	for key, value := range payload {
		preview[key] = value
	}
	if eve, ok := preview["eve"].(map[string]any); ok {
		evePreview := map[string]any{}
		for key, value := range eve {
			evePreview[key] = value
		}
		if _, has := evePreview["password"]; has {
			evePreview["password"] = "[redacted]"
		}
		preview["eve"] = evePreview
	}
	data, err := json.Marshal(preview)
	if err != nil {
		return "<unavailable>"
	}
	return string(data)
}

func (s *Service) runLabppTask(ctx context.Context, spec labppRunSpec, log *taskLogger) error {
	project := strings.TrimSpace(spec.WorkspaceSlug)
	if project == "" {
		project = strings.TrimSpace(spec.Username)
	}
	if project == "" {
		project = "default"
	}
	deployment := strings.TrimSpace(spec.Deployment)
	if deployment == "" {
		deployment = strings.TrimSpace(spec.Template)
	}
	labPath := strings.TrimSpace(spec.LabPath)
	if labPath == "" && strings.TrimSpace(spec.Template) != "" {
		stamp := time.Now().UTC().Format("20060102-1504")
		labPath = fmt.Sprintf(
			"/%s-%s/%s.unl",
			labppSafeFilename.ReplaceAllString(deployment, "-"),
			stamp,
			labppLabFilename(spec.Template),
		)
	}
	if labPath != "" {
		labPath = "/" + strings.TrimPrefix(labPath, "/")
	}
	templatesRoot := strings.TrimSpace(spec.TemplatesRoot)
	if templatesRoot == "" {
		templatesRoot = "/var/lib/skyforge/labpp-templates"
	}
	debugID := uuid.NewString()
	debugFingerprint := ""
	if spec.EvePassword != "" {
		sum := sha256.Sum256([]byte(spec.EvePassword))
		debugFingerprint = fmt.Sprintf("%x", sum)
	}
	payload := map[string]any{
		"action":           strings.ToUpper(spec.Action),
		"project":          project,
		"deployment":       deployment,
		"templatesRoot":    templatesRoot,
		"template":         spec.Template,
		"debugId":          debugID,
		"debugFingerprint": debugFingerprint,
		"eve": map[string]any{
			"url":      spec.EveURL,
			"username": spec.EveUsername,
			"password": spec.EvePassword,
		},
	}
	if labPath != "" {
		payload["labPath"] = labPath
	}
	if spec.ThreadCount > 0 {
		payload["threadCount"] = spec.ThreadCount
	}

	stdlog.Printf(
		"labpp payload context: action=%s labPath=%s templatesRoot=%s template=%s",
		spec.Action,
		labPath,
		spec.TemplatesRoot,
		spec.Template,
	)
	log.Infof(
		"LabPP payload context: action=%s labPath=%s templatesRoot=%s template=%s",
		spec.Action,
		labPath,
		spec.TemplatesRoot,
		spec.Template,
	)
	if spec.EvePassword != "" {
		log.Infof("LabPP EVE password fingerprint: %s", debugFingerprint)
		stdlog.Printf("labpp eve password fingerprint: %s", debugFingerprint)
	}
	log.Infof("LabPP debug id: %s", debugID)
	log.Infof("LabPP payload fields: project=%s deployment=%s template=%s templatesRoot=%s", project, deployment, spec.Template, spec.TemplatesRoot)
	log.Infof("LabPP payload preview: %s", labppPayloadPreview(payload))
	if payloadJSON, err := json.Marshal(payload); err == nil {
		stdlog.Printf("labpp payload json: %s", payloadJSON)
	}
	log.Infof("Starting labpp job (%s)", spec.Action)
	resp, body, err := labppAPIDo(ctx, spec.APIURL+"/jobs", payload, spec.Insecure)
	if err != nil {
		return fmt.Errorf("failed to reach labpp API: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("labpp API rejected request: %s", strings.TrimSpace(string(body)))
	}
	var job labppJob
	if err := json.Unmarshal(body, &job); err != nil || strings.TrimSpace(job.ID) == "" {
		return fmt.Errorf("labpp API returned invalid response")
	}
	if spec.TaskID > 0 && spec.WorkspaceCtx != nil {
		metaAny, _ := fromJSONMap(spec.Metadata)
		if metaAny == nil {
			metaAny = map[string]any{}
		}
		metaAny["labppJobId"] = job.ID
		metaAny["labppLabPath"] = spec.LabPath
		metaAny["labppTemplate"] = spec.Template
		metaAny["labppApiUrl"] = spec.APIURL
		metaUpdated, err := toJSONMap(metaAny)
		if err != nil {
			stdlog.Printf("labpp metadata encode: %v", err)
		} else {
			spec.Metadata = metaUpdated
			metaCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := updateTaskMetadata(metaCtx, s.db, spec.TaskID, metaUpdated); err != nil {
				stdlog.Printf("labpp metadata update: %v", err)
			}
			cancel()
		}
	}

	lastLog := ""
	lastLogAt := time.Now()
	lastStatus := ""
	lastStatusAt := time.Now()
	startedAt := time.Now()
	deadline := time.Now().Add(time.Duration(spec.MaxSeconds) * time.Second)
	if spec.MaxSeconds <= 0 {
		deadline = time.Now().Add(20 * time.Minute)
	}

	for {
		if spec.TaskID > 0 {
			canceled, meta := s.taskCanceled(ctx, spec.TaskID)
			if canceled {
				jobID := job.ID
				if jobID == "" {
					jobID = labppMetaString(meta, "labppJobId")
				}
				if jobID != "" {
					s.cancelLabppJob(ctx, spec.APIURL, jobID, spec.Insecure, log)
				}
				return fmt.Errorf("labpp job canceled")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("labpp job timed out")
		}

		getResp, getBody, err := labppAPIGet(ctx, fmt.Sprintf("%s/jobs/%s", spec.APIURL, job.ID), spec.Insecure)
		if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
			_ = json.Unmarshal(getBody, &job)
		}

		logResp, logBody, err := labppAPIGet(ctx, fmt.Sprintf("%s/jobs/%s/log", spec.APIURL, job.ID), spec.Insecure)
		if err == nil && logResp != nil && logResp.StatusCode >= 200 && logResp.StatusCode < 300 {
			nextLog := normalizeLabppLog(string(logBody))
			if nextLog != "" && nextLog != lastLog {
				diff := nextLog[len(lastLog):]
				if diff != "" {
					log.Infof(diff)
				}
				lastLog = nextLog
				lastLogAt = time.Now()
			}
		}

		status := strings.ToLower(strings.TrimSpace(derefString(job.Status)))
		if status == "" {
			status = strings.ToLower(strings.TrimSpace(derefString(job.State)))
		}
		if status == "" {
			status = "pending"
		}
		if status != lastStatus || time.Since(lastStatusAt) > 20*time.Second {
			log.Infof("LabPP status: %s (elapsed %s)", status, time.Since(startedAt).Truncate(time.Second))
			lastStatus = status
			lastStatusAt = time.Now()
		} else if status == "running" && time.Since(lastLogAt) > 30*time.Second && time.Since(lastStatusAt) > 20*time.Second {
			log.Infof("LabPP still running; waiting for node boot/config (elapsed %s)", time.Since(startedAt).Truncate(time.Second))
			lastStatusAt = time.Now()
		}
		if status == "running" && lastLog != "" {
			if strings.Contains(lastLog, "LabPP job completed with status SUCCESS") ||
				(strings.Contains(lastLog, "NODE-SETUP complete for all nodes") && (spec.Action == "start" || spec.Action == "e2e")) {
				log.Infof("LabPP status inferred as success from logs")
				if spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" {
					syncCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					if err := s.syncForwardLabppDevices(syncCtx, spec.WorkspaceCtx, spec.DeploymentID, spec.APIURL, job.ID, spec.Insecure); err != nil {
						stdlog.Printf("forward labpp sync: %v", err)
					}
					cancel()
				}
				return nil
			}
		}
		if status == "success" || status == "succeeded" || status == "failed" || status == "canceled" || status == "cancelled" {
			if status != "success" && status != "succeeded" {
				errText := ""
				if job.Error != nil {
					errText = strings.TrimSpace(*job.Error)
				}
				if isLabppBenignFailure(spec.Action, errText, lastLog) {
					log.Infof("LabPP action treated as success: %s", errText)
					return nil
				}
				if errText != "" {
					return errors.New(errText)
				}
				return fmt.Errorf("labpp job %s", status)
			}
			if spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" {
				syncCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				if err := s.syncForwardLabppDevices(syncCtx, spec.WorkspaceCtx, spec.DeploymentID, spec.APIURL, job.ID, spec.Insecure); err != nil {
					stdlog.Printf("forward labpp sync: %v", err)
				}
				cancel()
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

type containerlabRunSpec struct {
	TaskID      int
	APIURL      string
	Token       string
	Action      string
	LabName     string
	Environment map[string]string
	Topology    map[string]any
	Reconfigure bool
	SkipTLS     bool
}

func (s *Service) runContainerlabTask(ctx context.Context, spec containerlabRunSpec, log *taskLogger) error {
	if spec.TaskID > 0 {
		canceled, _ := s.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("containerlab job canceled")
		}
	}
	switch spec.Action {
	case "deploy":
		payload := containerlabDeployRequest{TopologyContent: spec.Topology}
		url := fmt.Sprintf("%s/api/v1/labs", spec.APIURL)
		if spec.Reconfigure {
			url += "?reconfigure=true"
		}
		resp, body, err := containerlabAPIDo(ctx, url, spec.Token, payload, spec.SkipTLS)
		if err != nil {
			return fmt.Errorf("failed to reach containerlab API: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("containerlab API rejected request: %s", strings.TrimSpace(string(body)))
		}
		log.Infof(string(body))
		return nil
	case "destroy":
		url := fmt.Sprintf("%s/api/v1/labs/%s", spec.APIURL, spec.LabName)
		resp, body, err := containerlabAPIDelete(ctx, url, spec.Token, spec.SkipTLS)
		if err != nil {
			return fmt.Errorf("failed to reach containerlab API: %w", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			log.Infof("Containerlab lab not found; destroy treated as success.")
			return nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("containerlab API rejected request: %s", strings.TrimSpace(string(body)))
		}
		if len(body) > 0 {
			log.Infof(string(body))
		}
		return nil
	default:
		return fmt.Errorf("unknown containerlab action")
	}
}

type tofuRunSpec struct {
	TaskID         int
	WorkspaceCtx   *workspaceContext
	WorkspaceSlug  string
	Username       string
	Cloud          string
	Action         string
	TemplateSource string
	TemplateRepo   string
	TemplatesDir   string
	Template       string
	Environment    map[string]any
}

func (s *Service) runTofuTask(ctx context.Context, spec tofuRunSpec, log *taskLogger) error {
	if spec.TaskID > 0 {
		canceled, _ := s.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("tofu job canceled")
		}
	}
	if spec.Template == "" {
		return fmt.Errorf("template is required")
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	ref, err := resolveTemplateRepoForProject(s.cfg, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo)
	if err != nil {
		return err
	}

	templatesDir := strings.Trim(strings.TrimSpace(spec.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = path.Join("cloud", "terraform", spec.Cloud)
	}
	if !isSafeRelativePath(templatesDir) {
		return fmt.Errorf("templatesDir must be a safe repo-relative path")
	}

	workRoot := s.cfg.Workspaces.DataDir
	if strings.TrimSpace(workRoot) == "" {
		workRoot = os.TempDir()
	}
	workDir := filepath.Join(workRoot, "tofu-workspaces", spec.WorkspaceSlug, spec.Username, spec.Template)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}

	sourceDir := path.Join(templatesDir, spec.Template)
	log.Infof("Syncing tofu template %s", sourceDir)
	if err := syncGiteaDirectory(s.cfg, ref.Owner, ref.Repo, sourceDir, ref.Branch, workDir); err != nil {
		return err
	}

	tofuPath, err := ensureTofuBinary()
	if err != nil {
		return err
	}

	env := map[string]string{}
	for k, v := range spec.Environment {
		env[k] = fmt.Sprint(v)
	}

	if err := runTofuCommand(ctx, log, tofuPath, workDir, env, "init", "-input=false", "-no-color"); err != nil {
		return err
	}

	switch spec.Action {
	case "plan":
		return runTofuCommand(ctx, log, tofuPath, workDir, env, "plan", "-input=false", "-no-color")
	case "apply":
		if err := runTofuCommand(ctx, log, tofuPath, workDir, env, "apply", "-auto-approve", "-input=false", "-no-color"); err != nil {
			return err
		}
		s.syncTofuState(ctx, spec, workDir, log)
		return nil
	case "destroy":
		if err := runTofuCommand(ctx, log, tofuPath, workDir, env, "destroy", "-auto-approve", "-input=false", "-no-color"); err != nil {
			if isTofuBenignFailure("destroy", err) {
				log.Infof("Tofu destroy treated as success: %v", err)
				return nil
			}
			return err
		}
		s.syncTofuState(ctx, spec, workDir, log)
		return nil
	default:
		return fmt.Errorf("unknown tofu action")
	}
}

func (s *Service) syncTofuState(ctx context.Context, spec tofuRunSpec, workDir string, log *taskLogger) {
	if spec.WorkspaceCtx == nil {
		return
	}
	stateKey := strings.TrimSpace(spec.WorkspaceCtx.workspace.TerraformStateKey)
	if stateKey == "" {
		log.Infof("Terraform state key not configured; skipping state upload.")
		return
	}
	statePath := filepath.Join(workDir, "terraform.tfstate")
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		log.Infof("Failed to read terraform state: %v", err)
		return
	}
	if err := putTerraformStateObject(ctx, s.cfg, "terraform-state", stateKey, stateBytes); err != nil {
		log.Infof("Failed to upload terraform state: %v", err)
		return
	}
	log.Infof("Terraform state synced to object storage.")
}

func runTofuCommand(ctx context.Context, log *taskLogger, binary string, workDir string, env map[string]string, args ...string) error {
	if binary == "" {
		return fmt.Errorf("tofu binary not found")
	}
	cmd := execCommandContext(ctx, binary, args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Infof(string(output))
	}
	if err != nil {
		return fmt.Errorf("tofu command failed: %w", err)
	}
	return nil
}

func isLabppBenignFailure(action string, errText string, logs string) bool {
	if action == "" {
		return false
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "stop" && action != "delete" && action != "destroy" {
		return false
	}
	candidate := strings.ToLower(strings.TrimSpace(errText))
	if candidate == "" {
		candidate = strings.ToLower(strings.TrimSpace(logs))
	}
	if candidate == "" {
		return false
	}
	for _, marker := range []string{
		"lab does not exists",
		"lab does not exist",
		"lab not found",
		"not found",
	} {
		if strings.Contains(candidate, marker) {
			return true
		}
	}
	return false
}

func isTofuBenignFailure(action string, err error) bool {
	if action != "destroy" || err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"no state file was found",
		"state does not exist",
		"no such file or directory",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

var execCommandContext = exec.CommandContext

var tofuBinaryOnce sync.Once
var tofuBinaryPath string
var tofuBinaryErr error

func ensureTofuBinary() (string, error) {
	tofuBinaryOnce.Do(func() {
		if path := strings.TrimSpace(os.Getenv("SKYFORGE_TOFU_PATH")); path != "" {
			tofuBinaryPath = path
			return
		}
		cacheRoot := filepath.Join(os.TempDir(), "skyforge-tools")
		tofuBinaryPath = filepath.Join(cacheRoot, "tofu")
		if _, err := os.Stat(tofuBinaryPath); err == nil {
			return
		}
		version := strings.TrimSpace(os.Getenv("SKYFORGE_TOFU_VERSION"))
		if version == "" {
			version = "1.7.2"
		}
		url := strings.TrimSpace(os.Getenv("SKYFORGE_TOFU_URL"))
		if url == "" {
			url = fmt.Sprintf("https://github.com/opentofu/opentofu/releases/download/v%s/tofu_%s_linux_amd64.zip", version, version)
		}
		if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
			tofuBinaryErr = err
			return
		}
		if err := downloadAndUnzipTofu(url, tofuBinaryPath); err != nil {
			tofuBinaryErr = err
			return
		}
	})
	return tofuBinaryPath, tofuBinaryErr
}

func downloadAndUnzipTofu(url string, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to download tofu: %s", resp.Status)
	}
	tmpFile := dest + ".zip"
	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := unzipFile(tmpFile, filepath.Dir(dest)); err != nil {
		return err
	}
	_ = os.Remove(tmpFile)
	if _, err := os.Stat(dest); err != nil {
		return err
	}
	return os.Chmod(dest, 0o755)
}

func unzipFile(archive string, destDir string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		target := filepath.Join(destDir, file.Name)
		if strings.HasSuffix(file.Name, "/") {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, file.Mode())
		if err != nil {
			_ = in.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = in.Close()
			_ = out.Close()
			return err
		}
		_ = in.Close()
		_ = out.Close()
	}
	return nil
}

func syncGiteaDirectory(cfg Config, owner, repo, dir, ref, dest string) error {
	entries, err := listGiteaDirectory(cfg, owner, repo, dir, ref)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		remotePath := path.Join(dir, name)
		localPath := filepath.Join(dest, name)
		switch entry.Type {
		case "dir":
			if err := os.MkdirAll(localPath, 0o755); err != nil {
				return err
			}
			if err := syncGiteaDirectory(cfg, owner, repo, remotePath, ref, localPath); err != nil {
				return err
			}
		case "file":
			contents, err := readGiteaFileBytes(cfg, owner, repo, remotePath, ref)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(localPath, contents, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func insecureTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}
