package taskengine

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
	"github.com/hashicorp/terraform-exec/tfexec"
)

type terraformTaskSpec struct {
	Action         string         `json:"action,omitempty"` // plan/apply/destroy
	Cloud          string         `json:"cloud,omitempty"`
	TemplateSource string         `json:"templateSource,omitempty"`
	TemplateRepo   string         `json:"templateRepo,omitempty"`
	TemplatesDir   string         `json:"templatesDir,omitempty"`
	Template       string         `json:"template,omitempty"`
	Deployment     string         `json:"deployment,omitempty"`
	DeploymentID   string         `json:"deploymentId,omitempty"`
	Environment    map[string]any `json:"environment,omitempty"`
}

type terraformRunSpec struct {
	TaskID         int
	UserScopeCtx   *userContext
	UserScopeSlug  string
	Username       string
	Cloud          string
	Action         string
	TemplateSource string
	TemplateRepo   string
	TemplatesDir   string
	Template       string
	Environment    map[string]any
}

func (e *Engine) dispatchTerraformTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn terraformTaskSpec
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

	cloud := strings.ToLower(strings.TrimSpace(specIn.Cloud))
	if cloud == "" {
		cloud = "aws"
	}
	action := strings.ToLower(strings.TrimSpace(specIn.Action))
	if action == "" {
		// Best-effort fallback for older callers.
		if after, ok := strings.CutPrefix(strings.ToLower(task.TaskType), "terraform-"); ok {
			action = after
		}
	}
	if action == "" {
		action = "plan"
	}

	runSpec := terraformRunSpec{
		TaskID:         task.ID,
		UserScopeCtx:   pc,
		UserScopeSlug:  strings.TrimSpace(pc.userScope.Slug),
		Username:       username,
		Cloud:          cloud,
		Action:         action,
		TemplateSource: strings.TrimSpace(specIn.TemplateSource),
		TemplateRepo:   strings.TrimSpace(specIn.TemplateRepo),
		TemplatesDir:   strings.TrimSpace(specIn.TemplatesDir),
		Template:       strings.TrimSpace(specIn.Template),
		Environment:    specIn.Environment,
	}
	actionStep := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if actionStep == "" {
		actionStep = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "terraform."+actionStep, func() error {
		return e.runTerraformTask(ctx, runSpec, log)
	})
}

func (e *Engine) runTerraformTask(ctx context.Context, spec terraformRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("terraform job canceled")
		}
	}
	if spec.Template == "" {
		return fmt.Errorf("template is required")
	}
	if spec.UserScopeCtx == nil {
		return fmt.Errorf("user context unavailable")
	}
	ref, err := e.resolveTemplateRepoForWorkspace(spec.UserScopeCtx, spec.TemplateSource, spec.TemplateRepo)
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

	workDir, err := os.MkdirTemp("", "skyforge-terraform-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	sourceDir := path.Join(templatesDir, spec.Template)
	log.Infof("Syncing terraform template %s", sourceDir)
	if err := e.syncGiteaDirectoryToFS(ctx, ref.Owner, ref.Repo, sourceDir, ref.Branch, workDir); err != nil {
		return err
	}

	terraformPath, err := e.ensureTerraformBinary()
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

	switch strings.ToLower(strings.TrimSpace(spec.Action)) {
	case "plan":
		return runTerraformCommand(ctx, log, terraformPath, workDir, env, "plan")
	case "apply":
		if err := runTerraformCommand(ctx, log, terraformPath, workDir, env, "apply"); err != nil {
			return err
		}
		e.syncTerraformState(ctx, spec, workDir, log)
		return nil
	case "destroy":
		if err := runTerraformCommand(ctx, log, terraformPath, workDir, env, "destroy"); err != nil {
			if isTerraformBenignFailure("destroy", err) {
				log.Infof("Terraform destroy treated as success: %v", err)
				return nil
			}
			return err
		}
		e.syncTerraformState(ctx, spec, workDir, log)
		return nil
	default:
		return fmt.Errorf("unknown terraform action")
	}
}

func (e *Engine) syncTerraformState(ctx context.Context, spec terraformRunSpec, workDir string, log Logger) {
	if log == nil {
		log = noopLogger{}
	}
	if spec.UserScopeCtx == nil {
		return
	}
	stateKey := strings.TrimSpace(spec.UserScopeCtx.userScope.TerraformStateKey)
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
	if err := putTerraformStateObject(ctx, e.cfg, "terraform-state", stateKey, stateBytes); err != nil {
		log.Infof("Failed to upload terraform state: %v", err)
		return
	}
	log.Infof("Terraform state synced to object storage.")
}

func runTerraformCommand(ctx context.Context, log Logger, binary string, workDir string, env map[string]string, action string) error {
	if log == nil {
		log = noopLogger{}
	}
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
	maps.Copy(envMap, env)
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

func (e *Engine) ensureTerraformBinary() (string, error) {
	terraformBinaryOnce.Do(func() {
		if p := strings.TrimSpace(e.cfg.TerraformBinaryPath); p != "" {
			terraformBinaryPath = p
			return
		}
		cacheRoot := filepath.Join(os.TempDir(), "skyforge-tools")
		terraformBinaryPath = filepath.Join(cacheRoot, "terraform")
		if _, err := os.Stat(terraformBinaryPath); err == nil {
			return
		}
		version := strings.TrimSpace(e.cfg.TerraformVersion)
		if version == "" {
			version = "1.9.8"
		}
		url := strings.TrimSpace(e.cfg.TerraformURL)
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

func (e *Engine) syncGiteaDirectoryToFS(ctx context.Context, owner, repo, dir, ref, dest string) error {
	entries, err := e.listGiteaDirectory(owner, repo, dir, ref)
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
			if err := e.syncGiteaDirectoryToFS(ctx, owner, repo, remotePath, ref, localPath); err != nil {
				return err
			}
		case "file":
			contents, err := e.readGiteaFileBytes(ctx, owner, repo, remotePath, ref)
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
