package taskengine

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type netlabValidateTaskSpec struct {
	TemplateSource string            `json:"templateSource,omitempty"`
	TemplateRepo   string            `json:"templateRepo,omitempty"`
	TemplatesDir   string            `json:"templatesDir,omitempty"`
	Template       string            `json:"template,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	SetOverrides   []string          `json:"setOverrides,omitempty"`
}

type netlabValidateRunSpec struct {
	TaskID         int
	WorkspaceCtx   *workspaceContext
	Username       string
	TemplateSource string
	TemplateRepo   string
	TemplatesDir   string
	Template       string
	Environment    map[string]string
	SetOverrides   []string
}

const defaultNetlabGeneratorImage = "ghcr.io/forwardnetworks/skyforge-netlab-generator:latest"

func (e *Engine) dispatchNetlabValidateTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn netlabValidateTaskSpec
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
	if strings.TrimSpace(specIn.TemplateSource) == "" {
		specIn.TemplateSource = "blueprints"
	}
	runSpec := netlabValidateRunSpec{
		TaskID:         task.ID,
		WorkspaceCtx:   pc,
		Username:       username,
		TemplateSource: strings.TrimSpace(specIn.TemplateSource),
		TemplateRepo:   strings.TrimSpace(specIn.TemplateRepo),
		TemplatesDir:   strings.TrimSpace(specIn.TemplatesDir),
		Template:       strings.TrimSpace(specIn.Template),
		Environment:    specIn.Environment,
		SetOverrides:   specIn.SetOverrides,
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "netlab.validate", func() error {
		return e.runNetlabValidateTask(ctx, runSpec, log)
	})
}

func (e *Engine) runNetlabValidateTask(ctx context.Context, spec netlabValidateRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if e == nil || e.db == nil {
		return fmt.Errorf("database unavailable")
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("validation canceled")
		}
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(spec.Template) == "" {
		return fmt.Errorf("netlab template is required")
	}

	log.Infof(
		"Netlab validate request: source=%s repo=%s templatesDir=%s template=%s",
		strings.TrimSpace(spec.TemplateSource),
		strings.TrimSpace(spec.TemplateRepo),
		strings.TrimSpace(spec.TemplatesDir),
		strings.TrimSpace(spec.Template),
	)

	image := strings.TrimSpace(e.cfg.NetlabGeneratorImage)
	if image == "" {
		image = defaultNetlabGeneratorImage
		log.Infof("Netlab generator image not configured; defaulting to %s", image)
	}
	pullPolicy := strings.TrimSpace(e.cfg.NetlabGeneratorPullPolicy)
	if pullPolicy == "" {
		pullPolicy = "IfNotPresent"
	}

	ns := clabernetesWorkspaceNamespace(spec.WorkspaceCtx.workspace.Slug)
	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return err
	}
	if err := kubeEnsureNamespaceImagePullSecret(ctx, ns, strings.TrimSpace(e.cfg.ImagePullSecretName), strings.TrimSpace(e.cfg.ImagePullSecretNamespace)); err != nil {
		return err
	}

	bundleB64, err := e.buildNetlabTopologyBundleB64(ctx, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template)
	if err != nil {
		return err
	}
	bundleB64 = strings.TrimSpace(bundleB64)
	if bundleB64 == "" {
		return fmt.Errorf("netlab topology bundle is empty")
	}
	// Kubernetes object size limit is ~1MiB; base64 expands.
	if len(bundleB64) > 900_000 {
		return fmt.Errorf("netlab topology bundle too large for in-cluster validation (%d bytes base64)", len(bundleB64))
	}
	if _, err := base64.StdEncoding.DecodeString(bundleB64); err != nil {
		return fmt.Errorf("invalid netlab topology bundle encoding: %w", err)
	}

	labels := map[string]string{
		"skyforge-task-id": fmt.Sprintf("%d", spec.TaskID),
		"skyforge-action":  "netlab-validate",
	}

	bundleCM := sanitizeKubeNameFallback(fmt.Sprintf("netlab-validate-%d-bundle", time.Now().Unix()%10_000), "netlab-validate-bundle")
	if err := kubeUpsertConfigMap(ctx, ns, bundleCM, map[string]string{
		"bundle.b64": bundleB64,
	}, labels); err != nil {
		return err
	}
	defer func() { _, _ = kubeDeleteConfigMap(context.Background(), ns, bundleCM) }()

	jobName := sanitizeKubeNameFallback(fmt.Sprintf("netlab-validate-%d", time.Now().Unix()%10_000), "netlab-validate")
	setOverrides := []string{}
	for _, raw := range spec.SetOverrides {
		if v := strings.TrimSpace(raw); v != "" {
			setOverrides = append(setOverrides, v)
		}
	}
	genEnv := map[string]string{
		"SKYFORGE_VALIDATE_ONLY":        "1",
		"SKYFORGE_NETLAB_BUNDLE_PATH":   "/input/bundle.b64",
		"SKYFORGE_NETLAB_TOPOLOGY_PATH": "topology.yml",
	}
	if len(setOverrides) > 0 {
		genEnv["SKYFORGE_NETLAB_SET_OVERRIDES"] = strings.Join(setOverrides, "\n")
	}
	for k, v := range spec.Environment {
		kk := strings.TrimSpace(k)
		if kk == "" {
			continue
		}
		up := strings.ToUpper(kk)
		if strings.HasPrefix(up, "NETLAB_") || strings.HasPrefix(kk, "netlab_") || up == "SKYFORGE_NETLAB_SET_OVERRIDES" {
			// Prefer explicit SetOverrides over environment-provided overrides.
			if up == "SKYFORGE_NETLAB_SET_OVERRIDES" && len(setOverrides) > 0 {
				continue
			}
			genEnv[kk] = v
		}
	}
	payload := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": ns,
			"labels": map[string]any{
				"app":              "skyforge-netlab-validate",
				"skyforge-task-id": fmt.Sprintf("%d", spec.TaskID),
			},
		},
		"spec": map[string]any{
			"backoffLimit":            0,
			"ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						"app": "skyforge-netlab-validate",
					},
				},
				"spec": map[string]any{
					"restartPolicy": "Never",
					"containers": []map[string]any{
						{
							"name":            "validator",
							"image":           image,
							"imagePullPolicy": pullPolicy,
							"env":             kubeEnvList(genEnv),
							"volumeMounts": []map[string]any{
								{"name": "input", "mountPath": "/input", "readOnly": true},
								{"name": "work", "mountPath": "/work"},
							},
						},
					},
					"volumes": []map[string]any{
						{
							"name": "input",
							"configMap": map[string]any{
								"name": bundleCM,
							},
						},
						{
							"name": "work",
							"emptyDir": map[string]any{
								"sizeLimit": "2Gi",
							},
						},
					},
				},
			},
		},
	}

	if err := kubeCreateJob(ctx, ns, payload); err != nil {
		return err
	}
	jobSucceeded := false
	defer func() {
		// Keep failed Jobs around until ttlSecondsAfterFinished for debugging.
		if jobSucceeded {
			_ = kubeDeleteJob(context.Background(), ns, jobName)
		}
	}()

	log.Infof("Netlab validate job created: %s", jobName)
	if err := kubeWaitJob(ctx, ns, jobName, log, func() bool {
		if spec.TaskID <= 0 || e == nil {
			return false
		}
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		return canceled
	}); err != nil {
		return err
	}
	jobSucceeded = true

	log.Infof("Netlab template validated successfully")
	return nil
}
