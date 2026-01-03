package skyforge

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
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

func (s *Service) queueTask(task *TaskRecord, runner func(ctx context.Context, log *taskLogger) error) {
	go func() {
		ctx := context.Background()
		if err := markTaskStarted(ctx, s.db, task.ID); err != nil {
			log.Printf("task start update failed: %v", err)
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
		if err := finishTask(ctx, s.db, task.ID, status, errMsg); err != nil {
			log.Printf("task finish update failed: %v", err)
		}
		if task.DeploymentID.Valid {
			finishedAt := time.Now().UTC()
			if err := s.updateDeploymentStatus(ctx, task.WorkspaceID, task.DeploymentID.String, status, &finishedAt); err != nil {
				log.Printf("deployment status update failed: %v", err)
			}
		}
	}()
}

type netlabRunSpec struct {
	WorkspaceCtx      *workspaceContext
	WorkspaceSlug     string
	Username        string
	Action          string
	Deployment      string
	WorkspaceRoot   string
	TemplateSource  string
	TemplateRepo    string
	TemplatesDir    string
	Template        string
	WorkspaceDir      string
	MultilabNumeric int
	StateRoot       string
	Cleanup         bool
	Server          NetlabServerConfig
}

func (s *Service) runNetlabTask(ctx context.Context, spec netlabRunSpec, log *taskLogger) error {
	if spec.Template != "" {
		log.Infof("Syncing netlab template %s", spec.Template)
		if spec.WorkspaceCtx == nil {
			return fmt.Errorf("workspace context unavailable")
		}
		if err := s.syncNetlabTopologyFile(ctx, spec.WorkspaceCtx, &spec.Server, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template, spec.WorkspaceDir, spec.Username); err != nil {
			return err
		}
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
	if spec.Cleanup {
		payload["cleanup"] = true
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

	lastLog := ""
	deadline := time.Now().Add(30 * time.Minute)
	for {
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
				if job.Error != nil && strings.TrimSpace(*job.Error) != "" {
					return errors.New(*job.Error)
				}
				return fmt.Errorf("netlab job %s", state)
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

type labppRunSpec struct {
	APIURL        string
	Insecure      bool
	Action        string
	WorkspaceSlug   string
	Deployment    string
	TemplatesRoot string
	Template      string
	LabPath       string
	ThreadCount   int
	EveURL        string
	EveUsername   string
	EvePassword   string
	MaxSeconds    int
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

func (s *Service) runLabppTask(ctx context.Context, spec labppRunSpec, log *taskLogger) error {
	payload := map[string]any{
		"action":        strings.ToUpper(spec.Action),
		"workspace":     spec.WorkspaceSlug,
		"deployment":    spec.Deployment,
		"templatesRoot": spec.TemplatesRoot,
		"template":      spec.Template,
		"eve": map[string]any{
			"url":      spec.EveURL,
			"username": spec.EveUsername,
			"password": spec.EvePassword,
		},
	}
	if spec.LabPath != "" {
		payload["labPath"] = spec.LabPath
	}
	if spec.ThreadCount > 0 {
		payload["threadCount"] = spec.ThreadCount
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

	lastLog := ""
	deadline := time.Now().Add(time.Duration(spec.MaxSeconds) * time.Second)
	if spec.MaxSeconds <= 0 {
		deadline = time.Now().Add(20 * time.Minute)
	}

	for {
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
			}
		}

		status := strings.ToLower(strings.TrimSpace(derefString(job.Status)))
		if status == "" {
			status = strings.ToLower(strings.TrimSpace(derefString(job.State)))
		}
		if status == "success" || status == "succeeded" || status == "failed" || status == "canceled" || status == "cancelled" {
			if status != "success" && status != "succeeded" {
				if job.Error != nil && strings.TrimSpace(*job.Error) != "" {
					return errors.New(*job.Error)
				}
				return fmt.Errorf("labpp job %s", status)
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

type containerlabRunSpec struct {
	APIURL      string
	Token       string
	Action      string
	LabName     string
	Topology    map[string]any
	Reconfigure bool
	SkipTLS     bool
}

func (s *Service) runContainerlabTask(ctx context.Context, spec containerlabRunSpec, log *taskLogger) error {
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
	WorkspaceCtx     *workspaceContext
	WorkspaceSlug    string
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
