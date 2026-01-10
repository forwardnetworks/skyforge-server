package skyforge

import (
	"archive/zip"
	"bytes"
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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"

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

	customArgs := []string{"--verbose", "--debug", "labpp", "--template-dir", templateDir, "--config-dir-base", configDirBase, "--labpp-config-file", configFile}
	if labPath != "" {
		customArgs = append(customArgs, "--lab-path", labPath)
	}
	if action != "" {
		customArgs = append(customArgs, "--action", strings.ToUpper(action))
	}
	if spec.ThreadCount > 0 {
		customArgs = append(customArgs, "--thread-count", strconv.Itoa(spec.ThreadCount))
	}

	labppS3Endpoint := strings.TrimSpace(s.cfg.LabppS3Endpoint)
	if labppS3Endpoint == "" {
		labppS3Endpoint = "http://minio:9000"
	}
	jobEnv := map[string]string{
		"LABPP_NETBOX_URL":          s.cfg.LabppNetboxURL,
		"LABPP_NETBOX_USERNAME":     s.cfg.LabppNetboxUsername,
		"LABPP_NETBOX_PASSWORD":     s.cfg.LabppNetboxPassword,
		"LABPP_NETBOX_TOKEN":        s.cfg.LabppNetboxToken,
		"LABPP_NETBOX_MGMT_SUBNET":  s.cfg.LabppNetboxMgmtSubnet,
		"LABPP_S3_ACCESS_KEY":       s.cfg.LabppS3AccessKey,
		"LABPP_S3_SECRET_KEY":       s.cfg.LabppS3SecretKey,
		"LABPP_S3_REGION":           s.cfg.LabppS3Region,
		"LABPP_S3_BUCKET":           s.cfg.LabppS3BucketName,
		"LABPP_S3_ENDPOINT":         labppS3Endpoint,
		"LABPP_S3_DISABLE_SSL":      fmt.Sprintf("%v", s.cfg.LabppS3DisableSSL),
		"LABPP_S3_DISABLE_CHECKSUM": fmt.Sprintf("%v", s.cfg.LabppS3DisableChecksum),
		"LABPP_EVE_HOST":            eveHost,
		"LABPP_CONFIG_FILE":         configFile,
		"LABPP_CONFIG_DIR_BASE":     configDirBase,
		"LABPP_TEMPLATES_DIR":       templateDir,
		"LABPP_LAB_PATH":            labPath,
		"LABPP_ACTION":              action,
		"LABPP_EVE_SSH_HOST":        eveHost,
		"LABPP_EVE_SSH_USER":        s.cfg.Labs.EveSSHUser,
		"LABPP_EVE_SSH_KEY_FILE":    s.cfg.Labs.EveSSHKeyFile,
		"LABPP_EVE_SSH_PORT":        "22",
		"LABPP_EVE_SSH_TUNNEL":      fmt.Sprintf("%v", s.cfg.Labs.EveSSHTunnel),
		"LABPP_EVE_SSH_NO_PROXY":    "localhost|127.0.0.1|minio|netbox|nautobot|gitea|skyforge-server|*.svc|*.cluster.local",
		"LABPP_SKIP_FORWARD":        "true",
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
		if isLabppBenignFailure(action, err.Error(), "") {
			log.Infof("LabPP %s treated as success: %v", action, err)
			return nil
		}
		return err
	}

	dataSourcesPath := ""
	if spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" && action == "" {
		dataSourcesDir := filepath.Join(strings.TrimSpace(s.cfg.PlatformDataDir), "labpp", "data-sources", spec.DeploymentID)
		csvPath, err := s.generateLabppDataSourcesCSV(ctx, spec.DeploymentID, templateDir, configDirBase, configFile, labPath, dataSourcesDir, log, eveHost)
		if err != nil {
			stdlog.Printf("labpp data_sources.csv generation failed: %v", err)
		} else {
			dataSourcesPath = csvPath
			forwardOverride := forwardOverridesFromEnv(spec.Environment)
			if err := s.syncForwardLabppDevicesFromCSV(ctx, spec.WorkspaceCtx, spec.DeploymentID, csvPath, forwardOverride); err != nil {
				stdlog.Printf("forward labpp sync: %v", err)
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
				stdlog.Printf("labpp metadata update: %v", err)
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
	if s.cfg.LabppNetboxToken != "" {
		lines = append(lines, fmt.Sprintf("netbox_token=%s", s.cfg.LabppNetboxToken))
	}
	if s.cfg.LabppNetboxMgmtSubnet != "" {
		lines = append(lines, fmt.Sprintf("netbox_mgmt_subnet_ip=%s", s.cfg.LabppNetboxMgmtSubnet))
	}
	if s.cfg.LabppS3AccessKey != "" {
		lines = append(lines, fmt.Sprintf("s3_access_key=%s", s.cfg.LabppS3AccessKey))
	}
	if s.cfg.LabppS3SecretKey != "" {
		lines = append(lines, fmt.Sprintf("s3_secret_key=%s", s.cfg.LabppS3SecretKey))
	}
	if s.cfg.LabppS3Region != "" {
		lines = append(lines, fmt.Sprintf("s3_region=%s", s.cfg.LabppS3Region))
	}
	if s.cfg.LabppS3BucketName != "" {
		lines = append(lines, fmt.Sprintf("s3_bucket_name=%s", s.cfg.LabppS3BucketName))
	}
	if s.cfg.LabppS3Endpoint != "" {
		lines = append(lines, fmt.Sprintf("s3_endpoint=%s", s.cfg.LabppS3Endpoint))
	}
	lines = append(lines, fmt.Sprintf("s3_disable_ssl=%v", s.cfg.LabppS3DisableSSL))
	lines = append(lines, fmt.Sprintf("s3_disable_checksum=%v", s.cfg.LabppS3DisableChecksum))
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
	customArgs := []string{"--verbose", "--debug", "labpp", "--template-dir", templateDir, "--config-dir-base", configDirBase, "--labpp-config-file", configFile, "--action", "DATA_SOURCES_CSV", "--sources-dir", dataSourcesDir}
	if labPath != "" {
		customArgs = append(customArgs, "--lab-path", labPath)
	}
	log.Infof("Generating labpp data_sources.csv")
	labppS3Endpoint := strings.TrimSpace(s.cfg.LabppS3Endpoint)
	if labppS3Endpoint == "" {
		labppS3Endpoint = "http://minio:9000"
	}
	jobEnv := map[string]string{
		"LABPP_NETBOX_URL":          s.cfg.LabppNetboxURL,
		"LABPP_NETBOX_USERNAME":     s.cfg.LabppNetboxUsername,
		"LABPP_NETBOX_PASSWORD":     s.cfg.LabppNetboxPassword,
		"LABPP_NETBOX_TOKEN":        s.cfg.LabppNetboxToken,
		"LABPP_NETBOX_MGMT_SUBNET":  s.cfg.LabppNetboxMgmtSubnet,
		"LABPP_S3_ACCESS_KEY":       s.cfg.LabppS3AccessKey,
		"LABPP_S3_SECRET_KEY":       s.cfg.LabppS3SecretKey,
		"LABPP_S3_REGION":           s.cfg.LabppS3Region,
		"LABPP_S3_BUCKET":           s.cfg.LabppS3BucketName,
		"LABPP_S3_ENDPOINT":         labppS3Endpoint,
		"LABPP_S3_DISABLE_SSL":      fmt.Sprintf("%v", s.cfg.LabppS3DisableSSL),
		"LABPP_S3_DISABLE_CHECKSUM": fmt.Sprintf("%v", s.cfg.LabppS3DisableChecksum),
		"LABPP_EVE_HOST":            eveHost,
		"LABPP_CONFIG_FILE":         configFile,
		"LABPP_CONFIG_DIR_BASE":     configDirBase,
		"LABPP_TEMPLATES_DIR":       templateDir,
		"LABPP_LAB_PATH":            labPath,
		"LABPP_ACTION":              "DATA_SOURCES_CSV",
		"LABPP_SOURCES_DIR":         dataSourcesDir,
		"LABPP_EVE_SSH_HOST":        eveHost,
		"LABPP_EVE_SSH_USER":        s.cfg.Labs.EveSSHUser,
		"LABPP_EVE_SSH_KEY_FILE":    s.cfg.Labs.EveSSHKeyFile,
		"LABPP_EVE_SSH_PORT":        "22",
		"LABPP_EVE_SSH_TUNNEL":      fmt.Sprintf("%v", s.cfg.Labs.EveSSHTunnel),
		"LABPP_EVE_SSH_NO_PROXY":    "localhost|127.0.0.1|minio|netbox|nautobot|gitea|skyforge-server|*.svc|*.cluster.local",
	}
	if err := s.runLabppJob(ctx, log, fmt.Sprintf("labpp-sources-%s", deploymentID), customArgs, jobEnv); err != nil {
		return "", err
	}
	csvPath := filepath.Join(dataSourcesDir, "data_sources.csv")
	if _, err := os.Stat(csvPath); err != nil {
		return "", fmt.Errorf("labpp data_sources.csv missing: %w", err)
	}
	return csvPath, nil
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
