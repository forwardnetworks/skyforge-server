package skyforge

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"
	"gopkg.in/yaml.v3"

	secretreader "encore.app/internal/secrets"
	"encore.app/storage"
	"encore.dev/rlog"
)

func (s *Service) notifyTaskEvent(ctx context.Context, task *TaskRecord, status string, errMsg string) error {
	if s == nil || s.db == nil || task == nil || !task.DeploymentID.Valid {
		return nil
	}
	// Only notify on deployment-scoped tasks for now (matches UI expectations).
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	meta, _ := fromJSONMap(task.Metadata)
	action := strings.TrimSpace(labppMetaString(meta, "action"))
	deploymentName := strings.TrimSpace(labppMetaString(meta, "deployment"))
	template := strings.TrimSpace(labppMetaString(meta, "template"))
	serverName := strings.TrimSpace(labppMetaString(meta, "server"))

	if deploymentName == "" {
		deploymentName = task.DeploymentID.String
	}

	title := ""
	message := ""
	priority := "low"
	typ := "DEPLOYMENT"
	category := "deployment"
	referenceID := fmt.Sprintf("%s:%d", task.DeploymentID.String, task.ID)

	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		title = fmt.Sprintf("Deployment %s started", deploymentName)
		message = strings.TrimSpace(fmt.Sprintf("action=%s template=%s server=%s task=%d", action, template, serverName, task.ID))
	case "success":
		title = fmt.Sprintf("Deployment %s succeeded", deploymentName)
		message = strings.TrimSpace(fmt.Sprintf("action=%s task=%d", action, task.ID))
	case "failed":
		title = fmt.Sprintf("Deployment %s failed", deploymentName)
		priority = "high"
		if strings.TrimSpace(errMsg) == "" {
			errMsg = task.Error.String
		}
		message = strings.TrimSpace(fmt.Sprintf("action=%s task=%d error=%s", action, task.ID, strings.TrimSpace(errMsg)))
	case "canceled":
		title = fmt.Sprintf("Deployment %s canceled", deploymentName)
		message = strings.TrimSpace(fmt.Sprintf("action=%s task=%d", action, task.ID))
	default:
		return nil
	}

	_, _, workspace, err := s.loadWorkspaceByKey(task.WorkspaceID)
	if err != nil {
		// Fall back to notifying just the actor.
		_, err := createNotification(ctx, s.db, task.CreatedBy, title, message, typ, category, referenceID, priority)
		return err
	}

	recipients := workspaceNotificationRecipients(workspace)
	if len(recipients) == 0 {
		recipients = []string{task.CreatedBy}
	}
	for _, username := range recipients {
		if _, err := createNotification(ctx, s.db, username, title, message, typ, category, referenceID, priority); err != nil {
			return err
		}
	}
	return nil
}

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

func (s *Service) appendTaskWarning(taskID int, warning string) {
	if s == nil || s.db == nil || taskID <= 0 {
		return
	}
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rec, err := getTask(ctx, s.db, taskID)
	if err != nil || rec == nil {
		return
	}
	meta, _ := fromJSONMap(rec.Metadata)
	if meta == nil {
		meta = map[string]any{}
	}

	var warnings []any
	if existing, ok := meta["warnings"].([]any); ok {
		warnings = existing
	}
	if warnings == nil {
		warnings = []any{}
	}
	for _, existing := range warnings {
		if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", existing)), warning) {
			meta["warningCount"] = len(warnings)
			if metaJSON, err := toJSONMap(meta); err == nil {
				_ = updateTaskMetadata(ctx, s.db, taskID, metaJSON)
			}
			return
		}
	}
	warnings = append(warnings, warning)
	meta["warnings"] = warnings
	meta["warningCount"] = len(warnings)
	if metaJSON, err := toJSONMap(meta); err == nil {
		_ = updateTaskMetadata(ctx, s.db, taskID, metaJSON)
	}
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
	_ = runner
	if s == nil || task == nil {
		return
	}
	s.enqueueTask(context.Background(), task)
}

func (s *Service) processQueuedTask(ctx context.Context, taskID int) error {
	if s == nil || s.db == nil || taskID <= 0 {
		return nil
	}
	task, err := getTask(ctx, s.db, taskID)
	if err != nil {
		return err
	}
	if task == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(task.Status), "queued") {
		return nil
	}

	unlock := func() {}
	if task.DeploymentID.Valid {
		workspaceID := strings.TrimSpace(task.WorkspaceID)
		deploymentID := strings.TrimSpace(task.DeploymentID.String)
		if workspaceID != "" && deploymentID != "" {
			lockKey := deploymentAdvisoryLockKey(workspaceID, deploymentID)
			for {
				ok, err := pgTryAdvisoryLock(ctx, s.db, lockKey)
				if err != nil {
					rlog.Error("deployment lock error", "err", err)
					time.Sleep(750 * time.Millisecond)
					continue
				}
				if !ok {
					time.Sleep(750 * time.Millisecond)
					continue
				}

				oldestQueuedID, err := getOldestQueuedDeploymentTaskID(ctx, s.db, workspaceID, deploymentID)
				if err != nil {
					_ = pgAdvisoryUnlock(context.Background(), s.db, lockKey)
					rlog.Error("deployment queue check error", "err", err)
					time.Sleep(750 * time.Millisecond)
					continue
				}
				if oldestQueuedID != 0 && oldestQueuedID != task.ID {
					_ = pgAdvisoryUnlock(context.Background(), s.db, lockKey)
					time.Sleep(750 * time.Millisecond)
					continue
				}

				unlock = func() { _ = pgAdvisoryUnlock(context.Background(), s.db, lockKey) }
				break
			}
		}
	} else {
		workspaceID := strings.TrimSpace(task.WorkspaceID)
		if workspaceID != "" {
			lockKey := workspaceAdvisoryLockKey(workspaceID)
			for {
				ok, err := pgTryAdvisoryLock(ctx, s.db, lockKey)
				if err != nil {
					rlog.Error("workspace lock error", "err", err)
					time.Sleep(750 * time.Millisecond)
					continue
				}
				if !ok {
					time.Sleep(750 * time.Millisecond)
					continue
				}

				oldestQueuedID, err := getOldestQueuedWorkspaceTaskID(ctx, s.db, workspaceID)
				if err != nil {
					_ = pgAdvisoryUnlock(context.Background(), s.db, lockKey)
					rlog.Error("workspace queue check error", "err", err)
					time.Sleep(750 * time.Millisecond)
					continue
				}
				if oldestQueuedID != 0 && oldestQueuedID != task.ID {
					_ = pgAdvisoryUnlock(context.Background(), s.db, lockKey)
					time.Sleep(750 * time.Millisecond)
					continue
				}

				unlock = func() { _ = pgAdvisoryUnlock(context.Background(), s.db, lockKey) }
				break
			}
		}
	}

	// If the task was canceled while waiting in the queue, exit early without running it.
	if rec, err := getTask(ctx, s.db, task.ID); err == nil && rec != nil && strings.EqualFold(rec.Status, "canceled") {
		if err := s.notifyTaskEvent(ctx, task, "canceled", ""); err != nil {
			rlog.Error("task cancel notification failed", "task_id", task.ID, "err", err)
		}
		if task.DeploymentID.Valid {
			finishedAt := time.Now().UTC()
			if err := s.updateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, "canceled", &finishedAt); err != nil {
				rlog.Error("deployment status update failed", "deployment_id", task.DeploymentID.String, "err", err)
			}
		}
		unlock()
		return nil
	}

	if ok, err := markTaskStarted(ctx, s.db, task.ID); err != nil {
		rlog.Error("task start update failed", "task_id", task.ID, "err", err)
		unlock()
		return nil
	} else if !ok {
		// Another worker started it (or it is no longer queued).
		unlock()
		return nil
	}
	if err := s.notifyTaskEvent(ctx, task, "running", ""); err != nil {
		rlog.Error("task start notification failed", "task_id", task.ID, "err", err)
	}
	taskStartedTotal.With(taskTypeLabels{TaskType: strings.TrimSpace(task.TaskType)}).Increment()
	startedAt := time.Now().UTC()
	if !task.CreatedAt.IsZero() {
		latency := startedAt.Sub(task.CreatedAt)
		if latency >= 0 {
			secs := latency.Seconds()
			taskQueueLatencySecondsLast.With(taskTypeLabels{TaskType: strings.TrimSpace(task.TaskType)}).Set(secs)
			taskQueueLatencySecondsTotal.With(taskTypeLabels{TaskType: strings.TrimSpace(task.TaskType)}).Add(secs)
		}
	}
	logger := &taskLogger{svc: s, taskID: task.ID}
	runErr := s.dispatchTask(ctx, task, logger)
	status := "success"
	errMsg := ""
	if runErr != nil {
		status = "failed"
		errMsg = runErr.Error()
		logger.Errorf("ERROR: %s", errMsg)
	}
	if rec, recErr := getTask(ctx, s.db, task.ID); recErr == nil && rec != nil && strings.EqualFold(rec.Status, "canceled") {
		status = "canceled"
		errMsg = ""
	}
	if status != "canceled" {
		if err := finishTask(ctx, s.db, task.ID, status, errMsg); err != nil {
			rlog.Error("task finish update failed", "task_id", task.ID, "err", err)
		}
	}
	finishType := strings.TrimSpace(task.TaskType)
	taskFinishedTotal.With(taskFinishLabels{TaskType: finishType, Status: status}).Increment()
	if status != "canceled" && !startedAt.IsZero() {
		duration := time.Since(startedAt)
		if duration >= 0 {
			secs := duration.Seconds()
			taskRunDurationSecondsLast.With(taskTypeLabels{TaskType: finishType}).Set(secs)
			taskRunDurationSecondsTotal.With(taskTypeLabels{TaskType: finishType}).Add(secs)
		}
	}
	if err := s.notifyTaskEvent(ctx, task, status, errMsg); err != nil {
		rlog.Error("task finish notification failed", "task_id", task.ID, "err", err)
	}
	if task.DeploymentID.Valid {
		finishedAt := time.Now().UTC()
		if err := s.updateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, status, &finishedAt); err != nil {
			rlog.Error("deployment status update failed", "deployment_id", task.DeploymentID.String, "err", err)
		}
	}
	unlock()
	return nil
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

type netlabC9sRunSpec struct {
	TaskID          int
	WorkspaceCtx    *workspaceContext
	WorkspaceSlug   string
	Username        string
	Environment     map[string]string
	Action          string // deploy|destroy
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
	Server          NetlabServerConfig
	TopologyPath    string
	ClabTarball     string
	K8sNamespace    string
	LabName         string
	TopologyName    string
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
			rlog.Error("netlab metadata encode", "err", err)
		} else {
			metaCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := updateTaskMetadata(metaCtx, s.db, spec.TaskID, metaJSON); err != nil {
				rlog.Error("netlab metadata update", "task_id", spec.TaskID, "err", err)
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
				errText := ""
				if job.Error != nil {
					errText = strings.TrimSpace(*job.Error)
				}
				// Best-effort: if netlab created enough state to report device mgmt IPs, still
				// push them into Forward so the workflow can proceed even if `netlab up` fails
				// late (e.g., config deploy / readiness checks).
				if strings.EqualFold(spec.Action, "up") || strings.EqualFold(spec.Action, "restart") {
					syncCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
					if err := s.maybeSyncForwardNetlabAfterRun(syncCtx, spec, log, apiURL); err != nil {
						log.Infof("forward netlab sync skipped: %v", err)
					} else {
						log.Infof("Forward netlab sync completed (post-failure).")
					}
					cancel()
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
				if _, _, err := s.publishNetlabClabTarball(ctx, spec, log, true); err != nil {
					return err
				}
			}
			if strings.EqualFold(spec.Action, "up") || strings.EqualFold(spec.Action, "restart") || strings.EqualFold(spec.Action, "create") {
				// For deployment-backed runs, ensure Forward credentials/devices are synced as soon as we have
				// a usable netlab status output. `create` runs can establish the per-device credential mapping
				// even before the nodes come up.
				if err := s.maybeSyncForwardNetlabAfterRun(ctx, spec, log, apiURL); err != nil {
					log.Infof("forward netlab sync skipped: %v", err)
				}
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

type netlabC9sTarball struct {
	ClabYAML   []byte
	NodeFiles  map[string]map[string][]byte // node -> relative path -> bytes
	RawPaths   []string
	TotalBytes int
}

func extractNetlabC9sTarball(data []byte) (*netlabC9sTarball, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("netlab tarball is empty")
	}

	rd := bytes.NewReader(data)
	var tr *tar.Reader
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, fmt.Errorf("failed to read gzip tarball: %w", err)
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(rd)
	}

	out := &netlabC9sTarball{
		NodeFiles: map[string]map[string][]byte{},
		RawPaths:  []string{},
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tarball: %w", err)
		}
		if hdr == nil || hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(hdr.Name), "./")
		if name == "" {
			continue
		}
		out.RawPaths = append(out.RawPaths, name)

		// Hard cap to avoid OOM on unexpected tarballs.
		if hdr.Size > 8<<20 {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(tr, 8<<20))
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry %s: %w", name, err)
		}
		out.TotalBytes += len(payload)

		if out.ClabYAML == nil && path.Base(name) == "clab.yml" {
			out.ClabYAML = payload
			continue
		}

		idx := strings.Index(name, "node_files/")
		if idx < 0 {
			continue
		}
		rel := strings.TrimPrefix(name[idx+len("node_files/"):], "/")
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) != 2 {
			continue
		}
		node := strings.TrimSpace(parts[0])
		nodeRel := strings.TrimSpace(parts[1])
		if node == "" || nodeRel == "" {
			continue
		}
		m := out.NodeFiles[node]
		if m == nil {
			m = map[string][]byte{}
			out.NodeFiles[node] = m
		}
		m[nodeRel] = payload
	}

	if len(out.ClabYAML) == 0 {
		return nil, fmt.Errorf("netlab tarball missing clab.yml")
	}
	if len(out.NodeFiles) == 0 {
		return nil, fmt.Errorf("netlab tarball missing node_files/")
	}
	return out, nil
}

func c9sConfigMapName(topologyName, node string) string {
	base := strings.TrimSpace(fmt.Sprintf("c9s-%s-%s-files", topologyName, node))
	return sanitizeKubeNameFallback(base, "c9s-files")
}

func (s *Service) runNetlabC9sTask(ctx context.Context, spec netlabC9sRunSpec, log *taskLogger) error {
	if spec.TaskID > 0 {
		canceled, _ := s.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("netlab c9s job canceled")
		}
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}

	action := strings.ToLower(strings.TrimSpace(spec.Action))
	switch action {
	case "", "deploy", "create", "start", "up":
		action = "deploy"
	case "destroy", "delete", "down", "stop":
		action = "destroy"
	default:
		return fmt.Errorf("invalid netlab c9s action (use deploy or destroy)")
	}

	ns := strings.TrimSpace(spec.K8sNamespace)
	if ns == "" {
		ns = clabernetesWorkspaceNamespace(spec.WorkspaceCtx.workspace.Slug)
	}
	labName := strings.TrimSpace(spec.LabName)
	if labName == "" {
		labName = containerlabLabName(spec.WorkspaceCtx.workspace.Slug, spec.Deployment)
	}
	topologyName := strings.TrimSpace(spec.TopologyName)
	if topologyName == "" {
		topologyName = clabernetesTopologyName(labName)
	}

	if action == "destroy" {
		clabSpec := clabernetesRunSpec{
			TaskID:       spec.TaskID,
			Action:       "destroy",
			Namespace:    ns,
			TopologyName: topologyName,
			LabName:      labName,
		}
		if err := s.runClabernetesTask(ctx, clabSpec, log); err != nil {
			return err
		}
		deleted, err := kubeDeleteConfigMapsByLabel(ctx, ns, map[string]string{
			"skyforge-c9s-topology": topologyName,
		})
		if err != nil {
			return err
		}
		if deleted > 0 {
			log.Infof("C9s configmaps deleted: %d", deleted)
		}
		return nil
	}

	if strings.TrimSpace(spec.Template) == "" {
		return fmt.Errorf("netlab template is required")
	}

	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return err
	}

	// 1) Sync template directory onto the netlab runner (workdir root contains topology.yml).
	topologyPath := strings.TrimSpace(spec.TopologyPath)
	if topologyPath == "" {
		log.Infof("Syncing netlab template %s", spec.Template)
		p, err := s.syncNetlabTopologyFile(ctx, spec.WorkspaceCtx, &spec.Server, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template, spec.WorkspaceDir, spec.Username)
		if err != nil {
			return err
		}
		topologyPath = p
	}

	// 2) Run netlab create to generate clab.yml + node_files.
	netlabCreate := netlabRunSpec{
		TaskID:          spec.TaskID,
		WorkspaceCtx:    spec.WorkspaceCtx,
		WorkspaceSlug:   spec.WorkspaceSlug,
		Username:        spec.Username,
		Environment:     spec.Environment,
		Action:          "create",
		Deployment:      spec.Deployment,
		DeploymentID:    spec.DeploymentID,
		WorkspaceRoot:   spec.WorkspaceRoot,
		TemplateSource:  spec.TemplateSource,
		TemplateRepo:    spec.TemplateRepo,
		TemplatesDir:    spec.TemplatesDir,
		WorkspaceDir:    spec.WorkspaceDir,
		MultilabNumeric: spec.MultilabNumeric,
		StateRoot:       spec.StateRoot,
		Server:          spec.Server,
		TopologyPath:    topologyPath,
	}
	if err := s.withTaskStep(ctx, spec.TaskID, "netlab.create", func() error {
		return s.runNetlabTask(ctx, netlabCreate, log)
	}); err != nil {
		return err
	}

	// 3) Export the clab tarball from the runner.
	tarballName := strings.TrimSpace(spec.ClabTarball)
	if tarballName == "" {
		tarballName = fmt.Sprintf("containerlab-%s.tar.gz", strings.TrimSpace(spec.Deployment))
	}
	netlabTar := netlabRunSpec{
		TaskID:          spec.TaskID,
		WorkspaceCtx:    spec.WorkspaceCtx,
		WorkspaceSlug:   spec.WorkspaceSlug,
		Username:        spec.Username,
		Environment:     spec.Environment,
		Action:          "clab-tarball",
		Deployment:      spec.Deployment,
		DeploymentID:    spec.DeploymentID,
		WorkspaceRoot:   spec.WorkspaceRoot,
		TemplateSource:  spec.TemplateSource,
		TemplateRepo:    spec.TemplateRepo,
		TemplatesDir:    spec.TemplatesDir,
		WorkspaceDir:    spec.WorkspaceDir,
		MultilabNumeric: spec.MultilabNumeric,
		StateRoot:       spec.StateRoot,
		Server:          spec.Server,
		TopologyPath:    topologyPath,
		ClabTarball:     tarballName,
	}
	if err := s.withTaskStep(ctx, spec.TaskID, "netlab.clab-tarball", func() error {
		return s.runNetlabTask(ctx, netlabTar, log)
	}); err != nil {
		return err
	}

	_, tarBytes, err := s.publishNetlabClabTarball(ctx, netlabTar, log, false)
	if err != nil {
		return err
	}
	tarball, err := extractNetlabC9sTarball(tarBytes)
	if err != nil {
		return err
	}

	// 4) Prepare containerlab topology for C9s. Set lab name and rewrite node_files binds to absolute paths.
	var topo map[string]any
	if err := yaml.Unmarshal(tarball.ClabYAML, &topo); err != nil {
		return fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	if topo == nil {
		topo = map[string]any{}
	}
	topo["name"] = labName

	// Ensure minimal Linux containers (typically Alpine-based) have sshd running so
	// SSH connectivity and Forward credential sync work out of the box.
	linuxSSHExec := `sh -c 'pgrep sshd >/dev/null 2>&1 && exit 0 || true; if command -v sshd >/dev/null 2>&1; then :; elif command -v apk >/dev/null 2>&1; then apk add --no-cache openssh-server openssh-client >/dev/null 2>&1 || apk add --no-cache openssh-server >/dev/null 2>&1 || true; elif command -v apt-get >/dev/null 2>&1; then apt-get update -qq >/dev/null 2>&1 || true; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 || true; fi; mkdir -p /var/run/sshd >/dev/null 2>&1 || true; ssh-keygen -A >/dev/null 2>&1 || true; printf "\nPermitRootLogin yes\nPasswordAuthentication yes\n" >> /etc/ssh/sshd_config 2>/dev/null || true; echo root:admin | chpasswd >/dev/null 2>&1 || true; ( /usr/sbin/sshd -e 2>/dev/null || sshd -e 2>/dev/null || true )'`
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
				if kind != "linux" {
					continue
				}
				image := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))
				if image == "" || (!strings.Contains(image, "alpine") && !strings.HasPrefix(image, "python")) {
					continue
				}
				existingAny, _ := cfg["exec"]
				out := []any{}
				if existingList, ok := existingAny.([]any); ok {
					out = append(out, existingList...)
				}
				already := false
				for _, item := range out {
					if strings.Contains(fmt.Sprintf("%v", item), "linux ssh") || strings.Contains(fmt.Sprintf("%v", item), "openssh-server") {
						already = true
						break
					}
				}
				if !already {
					out = append(out, linuxSSHExec)
				}
				cfg["exec"] = out
				nodes[node] = cfg
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	nodeMounts := map[string][]c9sFileFromConfigMap{}
	for node, files := range tarball.NodeFiles {
		if len(files) == 0 {
			continue
		}
		total := 0
		cmData := map[string]string{}
		mounts := make([]c9sFileFromConfigMap, 0, len(files))
		for rel, payload := range files {
			rel = strings.TrimSpace(rel)
			if rel == "" || len(payload) == 0 {
				continue
			}
			total += len(payload)
			key := strings.NewReplacer("/", "__", ":", "_", "\\", "_").Replace(rel)
			if key == "" {
				continue
			}
			if _, exists := cmData[key]; exists {
				continue
			}
			cmData[key] = string(payload)
			mountPath := path.Join(mountRoot, "node_files", node, rel)
			mounts = append(mounts, c9sFileFromConfigMap{
				ConfigMapName: c9sConfigMapName(topologyName, node),
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
		if total > 900<<10 {
			return fmt.Errorf("node_files for %s too large for a ConfigMap (%d bytes)", node, total)
		}
		if len(cmData) == 0 || len(mounts) == 0 {
			continue
		}
		if err := kubeUpsertConfigMap(ctx, ns, c9sConfigMapName(topologyName, node), cmData, map[string]string{
			"skyforge-c9s-topology": topologyName,
			"skyforge-c9s-node":     node,
		}); err != nil {
			return err
		}
		nodeMounts[node] = mounts
	}

	// Rewrite bind sources to the mounted file paths (only for node_files paths).
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				bindsAny, ok := cfg["binds"]
				if !ok {
					continue
				}
				rawBinds, ok := bindsAny.([]any)
				if !ok || len(rawBinds) == 0 {
					continue
				}
				out := make([]any, 0, len(rawBinds))
				for _, bindAny := range rawBinds {
					bind := strings.TrimSpace(fmt.Sprintf("%v", bindAny))
					if bind == "" {
						continue
					}
					parts := strings.SplitN(bind, ":", 2)
					if len(parts) != 2 {
						out = append(out, bind)
						continue
					}
					hostPath := strings.TrimSpace(parts[0])
					rest := parts[1]
					hostPath = strings.TrimPrefix(hostPath, "./")
					if strings.HasPrefix(hostPath, "node_files/") {
						newHost := path.Join(mountRoot, hostPath)
						out = append(out, newHost+":"+rest)
						continue
					}
					if !strings.HasPrefix(hostPath, "/") && hostPath != "" {
						s.appendTaskWarning(spec.TaskID, fmt.Sprintf("c9s: bind path %q for node %s is relative and not under node_files", hostPath, nodeName))
					}
					out = append(out, bind)
				}
				cfg["binds"] = out
				nodes[node] = cfg
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
	}

	topologyBytes, err := yaml.Marshal(topo)
	if err != nil {
		return fmt.Errorf("failed to encode clab.yml: %w", err)
	}

	clabSpec := clabernetesRunSpec{
		TaskID:             spec.TaskID,
		Action:             "deploy",
		Namespace:          ns,
		TopologyName:       topologyName,
		LabName:            labName,
		TopologyYAML:       string(topologyBytes),
		Environment:        spec.Environment,
		FilesFromConfigMap: nodeMounts,
	}
	return s.withTaskStep(ctx, spec.TaskID, "c9s.deploy", func() error {
		return s.runClabernetesTask(ctx, clabSpec, log)
	})
}

func (s *Service) maybeSyncForwardNetlabAfterRun(ctx context.Context, spec netlabRunSpec, log *taskLogger, apiURL string) error {
	if s == nil {
		return fmt.Errorf("service unavailable")
	}
	if log == nil {
		return fmt.Errorf("task logger unavailable")
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(spec.DeploymentID) == "" {
		// Only deployment-backed Netlab runs have stable deployment IDs.
		return fmt.Errorf("deployment id unavailable")
	}

	dep, err := s.getWorkspaceDeployment(ctx, spec.WorkspaceCtx.workspace.ID, strings.TrimSpace(spec.DeploymentID))
	if err != nil {
		return err
	}
	if dep == nil || dep.Type != "netlab" {
		return fmt.Errorf("netlab deployment not found")
	}

	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	payload := map[string]any{
		"action":        "status",
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

	postResp, body, err := netlabAPIDo(ctxReq, apiURL+"/jobs", payload)
	if err != nil {
		return fmt.Errorf("failed to reach netlab API: %w", err)
	}
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		return fmt.Errorf("netlab API rejected status request: %s", strings.TrimSpace(string(body)))
	}
	var statusJob netlabAPIJob
	if err := json.Unmarshal(body, &statusJob); err != nil || strings.TrimSpace(statusJob.ID) == "" {
		return fmt.Errorf("netlab status returned invalid response")
	}

	statusLog := ""
	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			break
		}

		getResp, getBody, err := netlabAPIGet(ctxReq, fmt.Sprintf("%s/jobs/%s", apiURL, statusJob.ID))
		if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
			_ = json.Unmarshal(getBody, &statusJob)
		}

		logResp, logBody, err := netlabAPIGet(ctxReq, fmt.Sprintf("%s/jobs/%s/log", apiURL, statusJob.ID))
		if err == nil && logResp != nil && logResp.StatusCode >= 200 && logResp.StatusCode < 300 {
			var lr netlabAPILog
			if err := json.Unmarshal(logBody, &lr); err == nil {
				statusLog = lr.Log
			}
		}

		state := strings.ToLower(strings.TrimSpace(statusJob.State))
		if state == "" {
			state = strings.ToLower(strings.TrimSpace(derefString(statusJob.Status)))
		}
		if state == "success" || state == "failed" || state == "canceled" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if strings.TrimSpace(statusLog) == "" {
		return fmt.Errorf("netlab status log unavailable")
	}

	if err := s.syncForwardNetlabDevices(ctxReq, spec.TaskID, spec.WorkspaceCtx, dep, statusLog); err != nil {
		return err
	}
	log.Infof("Forward netlab sync completed.")
	return nil
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

func (s *Service) publishNetlabClabTarball(ctx context.Context, spec netlabRunSpec, log *taskLogger, store bool) (string, []byte, error) {
	if spec.WorkspaceCtx == nil {
		return "", nil, fmt.Errorf("workspace context unavailable")
	}
	tarball := strings.TrimSpace(spec.ClabTarball)
	if tarball == "" {
		return "", nil, nil
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
		return "", nil, err
	}
	defer client.Close()

	out, err := runSSHCommand(client, fmt.Sprintf("base64 %q", remotePath), 2*time.Minute)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read clab tarball: %w", err)
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
		return "", nil, fmt.Errorf("failed to decode clab tarball: %w", err)
	}

	key := path.Join("netlab", spec.Deployment, path.Base(remotePath))
	if store {
		objectName := artifactObjectName(spec.WorkspaceCtx.workspace.ID, key)
		if err := storage.Write(ctx, &storage.WriteRequest{ObjectName: objectName, Data: payload}); err != nil {
			return "", nil, fmt.Errorf("failed to upload clab tarball: %w", err)
		}
		log.Infof("SKYFORGE_ARTIFACT clab_tarball=%s", key)
	}
	return key, payload, nil
}

type labppRunSpec struct {
	TaskID        int
	WorkspaceCtx  *workspaceContext
	DeploymentID  string
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
		labPath = labppLabPath(spec.Username, deployment, spec.Template, time.Now())
	}
	labPath = labppNormalizeFolderPath(labPath)
	labppRunnerPath := strings.TrimPrefix(strings.TrimSpace(labPath), "/")
	templatesRoot := strings.TrimSpace(spec.TemplatesRoot)
	if templatesRoot == "" {
		templatesRoot = "/var/lib/skyforge/labpp/templates"
	}
	action := strings.TrimSpace(spec.Action)
	if strings.EqualFold(action, "configure") {
		action = "config"
	}
	if strings.EqualFold(action, "e2e") {
		action = ""
	}
	if strings.EqualFold(action, "start") {
		action = ""
	}
	templateDir := filepath.Join(templatesRoot, spec.Template)
	if _, err := os.Stat(templateDir); err != nil {
		return fmt.Errorf("labpp template dir missing: %w", err)
	}
	configDirBase := strings.TrimSpace(s.cfg.LabppConfigDirBase)
	if configDirBase == "" {
		return fmt.Errorf("labpp config dir base is not configured")
	}
	if err := os.MkdirAll(configDirBase, 0o755); err != nil {
		return fmt.Errorf("failed to ensure labpp config dir base: %w", err)
	}

	eveHost := resolveLabppHost(spec.EveURL)
	if eveHost == "" {
		return fmt.Errorf("eve host unavailable for labpp")
	}
	configFile, err := s.writeLabppConfigFile(eveHost, spec.EveUsername, spec.EvePassword)
	if err != nil {
		return err
	}
	defer os.Remove(configFile)

	debugID := uuid.NewString()
	debugFingerprint := ""
	if spec.EvePassword != "" {
		sum := sha256.Sum256([]byte(spec.EvePassword))
		debugFingerprint = fmt.Sprintf("%x", sum)
	}
	log.Infof("LabPP debug id: %s", debugID)
	log.Infof("LabPP EVE password fingerprint: %s", debugFingerprint)
	log.Infof("LabPP run: action=%s labPath=%s templateDir=%s", action, labPath, templateDir)

	customArgs := []string{"--verbose", "--debug", "labpp", "--no-forwarding", "--template-dir", templateDir, "--config-dir-base", configDirBase, "--labpp-config-file", configFile}
	if labppRunnerPath != "" {
		customArgs = append(customArgs, "--lab-path", labppRunnerPath)
	}
	if action != "" {
		customArgs = append(customArgs, "--action", strings.ToUpper(action))
	}
	if spec.ThreadCount > 0 {
		customArgs = append(customArgs, "--thread-count", strconv.Itoa(spec.ThreadCount))
	}

	netboxURL := netboxInternalBaseURL(s.cfg)
	jobEnv := map[string]string{
		"LABPP_NETBOX_URL":         netboxURL,
		"LABPP_NETBOX_MGMT_SUBNET": s.cfg.LabppNetboxMgmtSubnet,
		"LABPP_EVE_HOST":           eveHost,
		"LABPP_CONFIG_FILE":        configFile,
		"LABPP_CONFIG_DIR_BASE":    configDirBase,
		"LABPP_TEMPLATES_DIR":      templateDir,
		"LABPP_LAB_PATH":           labppRunnerPath,
		"LABPP_ACTION":             action,
		"LABPP_EVE_SSH_HOST":       eveHost,
		"LABPP_EVE_SSH_USER":       s.cfg.Labs.EveSSHUser,
		"LABPP_EVE_SSH_KEY_FILE":   s.cfg.Labs.EveSSHKeyFile,
		"LABPP_EVE_SSH_PORT":       "22",
		"LABPP_EVE_SSH_TUNNEL":     fmt.Sprintf("%v", s.cfg.Labs.EveSSHTunnel),
		"LABPP_EVE_SSH_NO_PROXY":   "localhost|127.0.0.1|minio|netbox|nautobot|gitea|skyforge-server|*.svc|*.cluster.local",
		"LABPP_SKIP_FORWARD":       "true",
		"LABPP_DEPLOYMENT_ID":      strings.TrimSpace(spec.DeploymentID),
	}
	jobEnv["LABPP_NETBOX_USERNAME"] = s.cfg.LabppNetboxUsername
	jobEnv["LABPP_NETBOX_PASSWORD"] = s.cfg.LabppNetboxPassword
	jobEnv["LABPP_NETBOX_TOKEN"] = s.cfg.LabppNetboxToken
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_USERNAME"))
	}
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_USERNAME", "skyforge-labpp-netbox-username"); err == nil {
			jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(secret)
		}
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_PASSWORD"))
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_PASSWORD", "skyforge-labpp-netbox-password"); err == nil {
			jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(secret)
		}
	}
	if jobEnv["LABPP_NETBOX_TOKEN"] == "" {
		jobEnv["LABPP_NETBOX_TOKEN"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_TOKEN"))
	}
	if jobEnv["LABPP_NETBOX_TOKEN"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_TOKEN", "skyforge-labpp-netbox-token"); err == nil {
			jobEnv["LABPP_NETBOX_TOKEN"] = strings.TrimSpace(secret)
		}
	}
	if spec.ThreadCount > 0 {
		jobEnv["LABPP_THREAD_COUNT"] = strconv.Itoa(spec.ThreadCount)
	}
	for key, value := range spec.Environment {
		jobEnv[key] = value
	}

	log.Infof("Starting LabPP runner job (%s)", strings.Join(customArgs, " "))
	jobName := fmt.Sprintf("labpp-%d", spec.TaskID)
	if err := s.runLabppJob(ctx, log, jobName, customArgs, jobEnv); err != nil {
		// LabPP sometimes fails late while trying to contact Forward (often configured as localhost).
		// Skyforge owns Forward sync, so treat these as success to avoid reporting a failed run
		// after the lab has been successfully created/configured.
		if isLabppForwardFailure(err.Error()) {
			if s != nil {
				s.appendTaskWarning(spec.TaskID, fmt.Sprintf("LabPP forward checks failed (ignored): %s", strings.TrimSpace(err.Error())))
			}
			log.Infof("LabPP forward-check failure ignored: %v", err)
		} else if isLabppBenignFailure(action, err.Error(), "") {
			if s != nil {
				s.appendTaskWarning(spec.TaskID, fmt.Sprintf("LabPP benign failure treated as success: %s", strings.TrimSpace(err.Error())))
			}
			log.Infof("LabPP %s treated as success: %v", action, err)
			return nil
		} else {
			return err
		}
	}

	dataSourcesPath := ""
	shouldSyncForward := action == "" || strings.EqualFold(action, "upload") || strings.EqualFold(action, "create")
	if spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" && shouldSyncForward {
		dataSourcesDir := filepath.Join(strings.TrimSpace(s.cfg.PlatformDataDir), "labpp", "data-sources", spec.DeploymentID)
		csvPath, err := s.generateLabppDataSourcesCSV(ctx, spec.DeploymentID, templateDir, configDirBase, configFile, labPath, dataSourcesDir, log, eveHost)
		if err != nil {
			rlog.Error("labpp data_sources.csv generation failed", "task_id", spec.TaskID, "err", err)
		} else {
			dataSourcesPath = csvPath
			forwardOverride := forwardOverridesFromEnv(spec.Environment)
			startCollection := action == ""
			if err := s.syncForwardLabppDevicesFromCSV(ctx, spec.TaskID, spec.WorkspaceCtx, spec.DeploymentID, csvPath, startCollection, forwardOverride); err != nil {
				rlog.Error("forward labpp sync", "task_id", spec.TaskID, "err", err)
			}
		}
	}

	if spec.TaskID > 0 && spec.WorkspaceCtx != nil {
		metaAny, _ := fromJSONMap(spec.Metadata)
		if metaAny == nil {
			metaAny = map[string]any{}
		}
		metaAny["labppLabPath"] = labPath
		metaAny["labppTemplate"] = spec.Template
		if dataSourcesPath != "" {
			metaAny["labppDataSourcesCsv"] = dataSourcesPath
		}
		metaUpdated, err := toJSONMap(metaAny)
		if err == nil {
			spec.Metadata = metaUpdated
			metaCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := updateTaskMetadata(metaCtx, s.db, spec.TaskID, metaUpdated); err != nil {
				rlog.Error("labpp metadata update", "task_id", spec.TaskID, "err", err)
			}
			cancel()
		}
	}

	return nil
}

func resolveLabppHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		if strings.Contains(raw, "/") {
			raw = "https://" + strings.TrimPrefix(raw, "//")
		} else {
			return raw
		}
	}
	u, err := url.Parse(raw)
	if err == nil && u != nil && u.Hostname() != "" {
		return u.Hostname()
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "//")
	return strings.TrimSpace(strings.Split(raw, "/")[0])
}

func (s *Service) writeLabppConfigFile(eveHost, username, password string) (string, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("labpp eve credentials are required")
	}
	configDir := strings.TrimSpace(s.cfg.LabppConfigDirBase)
	if configDir == "" {
		configDir = os.TempDir()
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create labpp config dir: %w", err)
	}
	f, err := os.CreateTemp(configDir, "labpp-*.properties")
	if err != nil {
		return "", fmt.Errorf("failed to create labpp config file: %w", err)
	}
	defer f.Close()

	version := strings.TrimSpace(s.cfg.LabppConfigVersion)
	if version == "" {
		version = "1.0"
	}
	lines := []string{
		fmt.Sprintf("version=%s", version),
		fmt.Sprintf("username=%s", username),
		fmt.Sprintf("password=%s", password),
		fmt.Sprintf("server_url=https://%s", eveHost),
	}
	if s.cfg.LabppNetboxURL != "" {
		netboxURL := strings.TrimRight(s.cfg.LabppNetboxURL, "/")
		if !strings.Contains(netboxURL, "/netbox") {
			netboxURL = netboxURL + "/netbox"
		}
		lines = append(lines, fmt.Sprintf("netbox_server_url=%s", netboxURL))
	}
	if s.cfg.LabppNetboxUsername != "" {
		lines = append(lines, fmt.Sprintf("netbox_username=%s", s.cfg.LabppNetboxUsername))
	}
	if s.cfg.LabppNetboxPassword != "" {
		lines = append(lines, fmt.Sprintf("netbox_password=%s", s.cfg.LabppNetboxPassword))
	}
	if s.cfg.LabppNetboxMgmtSubnet != "" {
		lines = append(lines, fmt.Sprintf("netbox_mgmt_subnet_ip=%s", s.cfg.LabppNetboxMgmtSubnet))
	}
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", fmt.Errorf("failed to write labpp config file: %w", err)
	}
	return f.Name(), nil
}

func (s *Service) generateLabppDataSourcesCSV(ctx context.Context, deploymentID, templateDir, configDirBase, configFile, labPath, dataSourcesDir string, log *taskLogger, eveHost string) (string, error) {
	if dataSourcesDir == "" {
		dataSourcesDir = filepath.Join(os.TempDir(), "labpp-data-sources")
	}
	if err := os.MkdirAll(dataSourcesDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create data sources dir: %w", err)
	}
	customArgs := []string{"--verbose", "--debug", "labpp", "--no-forwarding", "--template-dir", templateDir, "--config-dir-base", configDirBase, "--labpp-config-file", configFile, "--action", "DATA_SOURCES_CSV", "--sources-dir", dataSourcesDir}
	labppRunnerPath := strings.TrimPrefix(strings.TrimSpace(labPath), "/")
	if labppRunnerPath != "" {
		customArgs = append(customArgs, "--lab-path", labppRunnerPath)
	}
	log.Infof("Generating labpp data_sources.csv")
	netboxURL := netboxInternalBaseURL(s.cfg)
	jobEnv := map[string]string{
		"LABPP_NETBOX_URL":         netboxURL,
		"LABPP_NETBOX_MGMT_SUBNET": s.cfg.LabppNetboxMgmtSubnet,
		"LABPP_EVE_HOST":           eveHost,
		"LABPP_CONFIG_FILE":        configFile,
		"LABPP_CONFIG_DIR_BASE":    configDirBase,
		"LABPP_TEMPLATES_DIR":      templateDir,
		"LABPP_LAB_PATH":           labppRunnerPath,
		"LABPP_ACTION":             "DATA_SOURCES_CSV",
		"LABPP_SOURCES_DIR":        dataSourcesDir,
		"LABPP_EVE_SSH_HOST":       eveHost,
		"LABPP_EVE_SSH_USER":       s.cfg.Labs.EveSSHUser,
		"LABPP_EVE_SSH_KEY_FILE":   s.cfg.Labs.EveSSHKeyFile,
		"LABPP_EVE_SSH_PORT":       "22",
		"LABPP_EVE_SSH_TUNNEL":     fmt.Sprintf("%v", s.cfg.Labs.EveSSHTunnel),
		"LABPP_EVE_SSH_NO_PROXY":   "localhost|127.0.0.1|minio|netbox|nautobot|gitea|skyforge-server|*.svc|*.cluster.local",
		"LABPP_SKIP_FORWARD":       "true",
	}
	jobEnv["LABPP_NETBOX_USERNAME"] = s.cfg.LabppNetboxUsername
	jobEnv["LABPP_NETBOX_PASSWORD"] = s.cfg.LabppNetboxPassword
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_USERNAME"))
	}
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_USERNAME", "skyforge-labpp-netbox-username"); err == nil {
			jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(secret)
		}
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_PASSWORD"))
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_PASSWORD", "skyforge-labpp-netbox-password"); err == nil {
			jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(secret)
		}
	}
	if err := s.runLabppJob(ctx, log, fmt.Sprintf("labpp-sources-%s", deploymentID), customArgs, jobEnv); err != nil {
		return "", err
	}
	csvPath := filepath.Join(dataSourcesDir, "data_sources.csv")
	if _, err := os.Stat(csvPath); err != nil {
		return "", fmt.Errorf("labpp data_sources.csv missing: %w", err)
	}
	if log != nil {
		// LabPP's DATA_SOURCES_CSV currently emits host+ssh_port rows (EVE host/port mapping).
		// Forward expects to connect to each device at port 22 through the configured jump server,
		// so rewrite the CSV to contain per-device management IPv4s when LabPP has already reserved
		// and logged those IPs from NetBox.
		if err := s.rewriteLabppDataSourcesCSVWithNetboxIPs(ctx, log, csvPath); err != nil {
			log.Infof("labpp data_sources.csv rewrite skipped: %v", err)
		}
	}
	return csvPath, nil
}

func (s *Service) rewriteLabppDataSourcesCSVWithNetboxIPs(ctx context.Context, log *taskLogger, csvPath string) error {
	if s == nil || s.db == nil || log == nil || log.taskID <= 0 {
		return fmt.Errorf("task logging unavailable")
	}

	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(records) < 2 {
		return nil
	}

	header := make([]string, len(records[0]))
	for i, value := range records[0] {
		header[i] = strings.ToLower(strings.TrimSpace(value))
	}
	findIndex := func(names ...string) int {
		for _, name := range names {
			for idx, value := range header {
				if value == name {
					return idx
				}
			}
		}
		return -1
	}
	nameIdx := findIndex("name")
	if nameIdx == -1 {
		nameIdx = 0
	}
	ipIdx := findIndex("ip_address", "mgmt_ip", "mgmt_ip_address", "management_ip", "management_ipv4", "ip")
	if ipIdx == -1 {
		return nil
	}

	// Only rewrite when the CSV isn't already using IPv4 addresses.
	needsRewrite := false
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) <= ipIdx {
			continue
		}
		raw := strings.TrimSpace(row[ipIdx])
		if ip := net.ParseIP(raw); ip == nil || ip.To4() == nil {
			needsRewrite = true
			break
		}
	}
	if !needsRewrite {
		return nil
	}

	logs, err := listTaskLogs(ctx, s.db, log.taskID, 5000)
	if err != nil {
		return err
	}

	// Example line (from LabPP NetBox allocator):
	// "**dal_VMX_VFP_1: Received Ip 10.255.0.2/24 available for the node"
	ipLine := regexp.MustCompile(`\*\*([A-Za-z0-9_.-]+):\s*Received Ip\s+([0-9.]+)/`)
	ipByName := map[string]string{}
	for _, entry := range logs {
		matches := ipLine.FindStringSubmatch(entry.Output)
		if len(matches) != 3 {
			continue
		}
		name := strings.TrimSpace(matches[1])
		ip := strings.TrimSpace(matches[2])
		if name == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		ipByName[name] = parsed.String()
	}
	if len(ipByName) == 0 {
		return fmt.Errorf("no netbox ip assignments found in task logs")
	}

	out := [][]string{{"name", "ip_address"}}
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) <= nameIdx {
			continue
		}
		name := strings.TrimSpace(row[nameIdx])
		if name == "" {
			continue
		}
		ip, ok := ipByName[name]
		if !ok {
			return fmt.Errorf("missing netbox ip assignment for %q", name)
		}
		out = append(out, []string{name, ip})
	}
	if len(out) <= 1 {
		return fmt.Errorf("no rows to rewrite")
	}

	tmp := csvPath + ".tmp"
	outFile, err := os.Create(tmp)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(outFile)
	if err := writer.WriteAll(out); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := outFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, csvPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	log.Infof("Rewrote labpp data_sources.csv with netbox management IPv4s.")
	return nil
}

func forwardOverridesFromEnv(env map[string]string) *forwardCredentials {
	if len(env) == 0 {
		return nil
	}
	override := &forwardCredentials{}
	set := func(field *string, key string) {
		if value, ok := env[key]; ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				*field = trimmed
			}
		}
	}
	set(&override.BaseURL, "LABPP_FORWARD_URL")
	set(&override.BaseURL, "LABPP_FORWARD_BASE_URL")
	set(&override.Username, "LABPP_FORWARD_USERNAME")
	set(&override.Password, "LABPP_FORWARD_PASSWORD")
	set(&override.DeviceUsername, "LABPP_FORWARD_DEVICE_USERNAME")
	set(&override.DevicePassword, "LABPP_FORWARD_DEVICE_PASSWORD")
	set(&override.CollectorID, "LABPP_FORWARD_COLLECTOR_ID")
	if override.BaseURL == "" && override.Username == "" && override.Password == "" &&
		override.DeviceUsername == "" && override.DevicePassword == "" && override.CollectorID == "" {
		return nil
	}
	return override
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
		log.Infof("%s", string(body))
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
			log.Infof("%s", string(body))
		}
		return nil
	default:
		return fmt.Errorf("unknown containerlab action")
	}
}

type clabernetesRunSpec struct {
	TaskID             int
	Action             string
	Namespace          string
	TopologyName       string
	LabName            string
	Template           string
	TopologyYAML       string
	Environment        map[string]string
	FilesFromConfigMap map[string][]c9sFileFromConfigMap
}

type c9sFileFromConfigMap struct {
	ConfigMapName string `json:"configMapName,omitempty"`
	ConfigMapPath string `json:"configMapPath,omitempty"`
	FilePath      string `json:"filePath,omitempty"`
	Mode          string `json:"mode,omitempty"` // read|execute
}

func (s *Service) runClabernetesTask(ctx context.Context, spec clabernetesRunSpec, log *taskLogger) error {
	if spec.TaskID > 0 {
		canceled, _ := s.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("clabernetes job canceled")
		}
	}
	ns := strings.TrimSpace(spec.Namespace)
	if ns == "" {
		return fmt.Errorf("k8s namespace is required")
	}
	name := strings.TrimSpace(spec.TopologyName)
	if name == "" {
		return fmt.Errorf("topology name is required")
	}

	switch spec.Action {
	case "deploy":
		log.Infof("Clabernetes deploy: namespace=%s topology=%s", ns, name)
		if err := kubeEnsureNamespace(ctx, ns); err != nil {
			return err
		}
		if _, err := kubeDeleteClabernetesTopology(ctx, ns, name); err != nil {
			return err
		}
		if len(spec.FilesFromConfigMap) > 0 {
			log.Infof("Clabernetes file mounts: nodes=%d", len(spec.FilesFromConfigMap))
		}
		payload := map[string]any{
			"apiVersion": "clabernetes.containerlab.dev/v1alpha1",
			"kind":       "Topology",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
				"labels": map[string]any{
					"skyforge-managed": "true",
				},
			},
			"spec": map[string]any{
				"definition": map[string]any{
					"containerlab": spec.TopologyYAML,
				},
			},
		}
		if len(spec.FilesFromConfigMap) > 0 {
			files := map[string]any{}
			for node, entries := range spec.FilesFromConfigMap {
				node = strings.TrimSpace(node)
				if node == "" || len(entries) == 0 {
					continue
				}
				out := make([]any, 0, len(entries))
				for _, entry := range entries {
					if strings.TrimSpace(entry.ConfigMapName) == "" || strings.TrimSpace(entry.FilePath) == "" {
						continue
					}
					item := map[string]any{
						"configMapName": strings.TrimSpace(entry.ConfigMapName),
						"filePath":      strings.TrimSpace(entry.FilePath),
					}
					if strings.TrimSpace(entry.ConfigMapPath) != "" {
						item["configMapPath"] = strings.TrimSpace(entry.ConfigMapPath)
					}
					if strings.TrimSpace(entry.Mode) != "" {
						item["mode"] = strings.TrimSpace(entry.Mode)
					}
					out = append(out, item)
				}
				if len(out) > 0 {
					files[node] = out
				}
			}
			if len(files) > 0 {
				specAny := payload["spec"].(map[string]any)
				specAny["deployment"] = map[string]any{
					"filesFromConfigMap": files,
				}
			}
		}
		if err := kubeCreateClabernetesTopology(ctx, ns, payload); err != nil {
			return err
		}

		started := time.Now()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("clabernetes deploy canceled")
			case <-ticker.C:
				if spec.TaskID > 0 {
					canceled, _ := s.taskCanceled(ctx, spec.TaskID)
					if canceled {
						return fmt.Errorf("clabernetes job canceled")
					}
				}
				topo, _, err := kubeGetClabernetesTopology(ctx, ns, name)
				if err != nil {
					log.Errorf("Topology status error: %v", err)
					continue
				}
				if topo != nil && topo.Status.TopologyReady {
					log.Infof("Topology is ready (elapsed %s)", time.Since(started).Truncate(time.Second))
					return nil
				}
				if time.Since(started) >= 15*time.Minute {
					return fmt.Errorf("clabernetes deploy timed out after %s", time.Since(started).Truncate(time.Second))
				}
				log.Infof("Waiting for topology to become ready (elapsed %s)", time.Since(started).Truncate(time.Second))
			}
		}
	case "destroy":
		log.Infof("Clabernetes destroy: namespace=%s topology=%s", ns, name)
		deleted, err := kubeDeleteClabernetesTopology(ctx, ns, name)
		if err != nil {
			return err
		}
		if !deleted {
			log.Infof("Topology not found; destroy treated as success.")
			return nil
		}
		started := time.Now()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("clabernetes destroy canceled")
			case <-ticker.C:
				if spec.TaskID > 0 {
					canceled, _ := s.taskCanceled(ctx, spec.TaskID)
					if canceled {
						return fmt.Errorf("clabernetes job canceled")
					}
				}
				topo, status, err := kubeGetClabernetesTopology(ctx, ns, name)
				if err != nil {
					log.Errorf("Topology status error: %v", err)
					continue
				}
				if topo == nil && status == http.StatusNotFound {
					log.Infof("Topology deleted (elapsed %s)", time.Since(started).Truncate(time.Second))
					return nil
				}
				if time.Since(started) >= 5*time.Minute {
					return fmt.Errorf("clabernetes destroy timed out after %s", time.Since(started).Truncate(time.Second))
				}
				log.Infof("Waiting for topology deletion (elapsed %s)", time.Since(started).Truncate(time.Second))
			}
		}
	default:
		return fmt.Errorf("unknown clabernetes action")
	}
}

type terraformRunSpec struct {
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

func (s *Service) runTerraformTask(ctx context.Context, spec terraformRunSpec, log *taskLogger) error {
	if spec.TaskID > 0 {
		canceled, _ := s.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("terraform job canceled")
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
	workDir := filepath.Join(workRoot, "terraform-workspaces", spec.WorkspaceSlug, spec.Username, spec.Template)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}

	sourceDir := path.Join(templatesDir, spec.Template)
	log.Infof("Syncing terraform template %s", sourceDir)
	if err := syncGiteaDirectory(s.cfg, ref.Owner, ref.Repo, sourceDir, ref.Branch, workDir); err != nil {
		return err
	}

	terraformPath, err := ensureTerraformBinary()
	if err != nil {
		return err
	}

	env := map[string]string{}
	for k, v := range spec.Environment {
		env[k] = fmt.Sprint(v)
	}

	if err := runTerraformCommand(ctx, log, terraformPath, workDir, env, "init"); err != nil {
		return err
	}

	switch spec.Action {
	case "plan":
		return runTerraformCommand(ctx, log, terraformPath, workDir, env, "plan")
	case "apply":
		if err := runTerraformCommand(ctx, log, terraformPath, workDir, env, "apply"); err != nil {
			return err
		}
		s.syncTerraformState(ctx, spec, workDir, log)
		return nil
	case "destroy":
		if err := runTerraformCommand(ctx, log, terraformPath, workDir, env, "destroy"); err != nil {
			if isTerraformBenignFailure("destroy", err) {
				log.Infof("Terraform destroy treated as success: %v", err)
				return nil
			}
			return err
		}
		s.syncTerraformState(ctx, spec, workDir, log)
		return nil
	default:
		return fmt.Errorf("unknown terraform action")
	}
}

func (s *Service) syncTerraformState(ctx context.Context, spec terraformRunSpec, workDir string, log *taskLogger) {
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

func runTerraformCommand(ctx context.Context, log *taskLogger, binary string, workDir string, env map[string]string, action string) error {
	if binary == "" {
		return fmt.Errorf("terraform binary not found")
	}
	tf, err := tfexec.NewTerraform(workDir, binary)
	if err != nil {
		return fmt.Errorf("failed to init terraform exec: %w", err)
	}
	envMap := map[string]string{}
	for _, item := range os.Environ() {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	for k, v := range env {
		envMap[k] = v
	}
	if _, ok := envMap["TF_CLI_ARGS_init"]; !ok {
		envMap["TF_CLI_ARGS_init"] = "-input=false -no-color"
	}
	if _, ok := envMap["TF_CLI_ARGS_plan"]; !ok {
		envMap["TF_CLI_ARGS_plan"] = "-input=false -no-color"
	}
	if _, ok := envMap["TF_CLI_ARGS_apply"]; !ok {
		envMap["TF_CLI_ARGS_apply"] = "-auto-approve -input=false -no-color"
	}
	if _, ok := envMap["TF_CLI_ARGS_destroy"]; !ok {
		envMap["TF_CLI_ARGS_destroy"] = "-auto-approve -input=false -no-color"
	}
	if err := tf.SetEnv(envMap); err != nil {
		return fmt.Errorf("failed to configure terraform env: %w", err)
	}
	var output bytes.Buffer
	tf.SetStdout(&output)
	tf.SetStderr(&output)

	switch action {
	case "init":
		err = tf.Init(ctx)
	case "plan":
		_, err = tf.Plan(ctx)
	case "apply":
		err = tf.Apply(ctx)
	case "destroy":
		err = tf.Destroy(ctx)
	default:
		return fmt.Errorf("unknown terraform action")
	}
	if output.Len() > 0 {
		log.Infof("%s", output.String())
	}
	if err != nil {
		return fmt.Errorf("terraform command failed: %w", err)
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

func isLabppForwardFailure(errText string) bool {
	candidate := strings.ToLower(strings.TrimSpace(errText))
	if candidate == "" {
		return false
	}
	for _, marker := range []string{
		"connect to http://localhost",
		"connect to http://localhost:80",
		"no forward properties file found",
		"please provide one through the --fwd-config option",
		"fwd init helps to create these",
		"runsnapshotchecks",
		"getnetworkwithname",
		"fwdapi.getnetworks",
		"http host connect exception",
	} {
		if strings.Contains(candidate, marker) {
			return true
		}
	}
	return false
}

func isTerraformBenignFailure(action string, err error) bool {
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

var terraformBinaryOnce sync.Once
var terraformBinaryPath string
var terraformBinaryErr error

func ensureTerraformBinary() (string, error) {
	terraformBinaryOnce.Do(func() {
		if path := strings.TrimSpace(os.Getenv("SKYFORGE_TERRAFORM_PATH")); path != "" {
			terraformBinaryPath = path
			return
		}
		cacheRoot := filepath.Join(os.TempDir(), "skyforge-tools")
		terraformBinaryPath = filepath.Join(cacheRoot, "terraform")
		if _, err := os.Stat(terraformBinaryPath); err == nil {
			return
		}
		version := strings.TrimSpace(os.Getenv("SKYFORGE_TERRAFORM_VERSION"))
		if version == "" {
			version = "1.9.8"
		}
		url := strings.TrimSpace(os.Getenv("SKYFORGE_TERRAFORM_URL"))
		if url == "" {
			url = fmt.Sprintf("https://releases.hashicorp.com/terraform/%s/terraform_%s_linux_amd64.zip", version, version)
		}
		if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
			terraformBinaryErr = err
			return
		}
		if err := downloadAndUnzipTerraform(url, terraformBinaryPath); err != nil {
			terraformBinaryErr = err
			return
		}
	})
	return terraformBinaryPath, terraformBinaryErr
}

func downloadAndUnzipTerraform(url string, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to download terraform: %s", resp.Status)
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
