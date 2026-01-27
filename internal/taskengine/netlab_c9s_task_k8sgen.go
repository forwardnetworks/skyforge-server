package taskengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"
)

type netlabC9sManifest struct {
	ClabYAML string `json:"clabYAML"`
	Nodes    map[string]struct {
		ConfigMapName string `json:"configMapName"`
		Files         []struct {
			Key string `json:"key"`
			Rel string `json:"rel"`
		} `json:"files"`
	} `json:"nodes"`
	SharedFiles *struct {
		ConfigMapName string `json:"configMapName"`
		Files         []struct {
			Key string `json:"key"`
			Rel string `json:"rel"`
		} `json:"files"`
	} `json:"sharedFiles,omitempty"`
	StartupConfigs *struct {
		ConfigMapName string `json:"configMapName"`
		Files         []struct {
			Key string `json:"key"`
			Rel string `json:"rel"`
		} `json:"files"`
	} `json:"startupConfigs,omitempty"`
}

// runNetlabC9sTaskK8sGenerator runs a netlab generator job inside the workspace namespace,
// waits for it to complete, then reads the generated manifest/configmaps.
//
// Contract:
// - Generator job reads `/input/bundle.b64` (a tar.gz base64) and extracts into /work.
// - Generator job runs `netlab create` and emits a clab.yml + node_files.
// - Generator job writes a ConfigMap named `c9s-<topologyName>-manifest` containing `manifest.json`.
// - `manifest.json` includes:
//   - `clabYAML` (string; contents of clab.yml)
//   - `nodes` mapping node -> {configMapName, files:[{key,rel}]}
//
// The worker uses this to mount node_files into clabernetes node pods without needing a tarball.
func (e *Engine) runNetlabC9sTaskK8sGenerator(ctx context.Context, spec netlabC9sRunSpec, topologyPath, tarballName string, log Logger) ([]byte, map[string][]c9sFileFromConfigMap, error) {
	if log == nil {
		log = noopLogger{}
	}
	if e == nil {
		return nil, nil, fmt.Errorf("engine unavailable")
	}

	image := strings.TrimSpace(e.cfg.NetlabGeneratorImage)
	if image == "" {
		return nil, nil, fmt.Errorf("netlab-c9s generator mode is k8s but NetlabGeneratorImage is not configured (set ENCORE_CFG_SKYFORGE.NetlabGenerator.GeneratorImage)")
	}
	pullPolicy := strings.TrimSpace(e.cfg.NetlabGeneratorPullPolicy)
	if pullPolicy == "" {
		pullPolicy = "IfNotPresent"
	}
	if spec.WorkspaceCtx == nil {
		return nil, nil, fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(spec.Template) == "" {
		return nil, nil, fmt.Errorf("netlab template is required")
	}

	ns := strings.TrimSpace(spec.K8sNamespace)
	if ns == "" {
		ns = clabernetesWorkspaceNamespace(spec.WorkspaceCtx.workspace.Slug)
	}
	topologyName := strings.TrimSpace(spec.TopologyName)
	if topologyName == "" {
		topologyName = clabernetesTopologyName(strings.TrimSpace(spec.LabName))
	}

	// Build the flattened topology bundle (tar.gz base64). This is copied into the generator pod
	// via a ConfigMap.
	bundleB64, err := e.buildNetlabTopologyBundleB64(ctx, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template)
	if err != nil {
		return nil, nil, err
	}
	bundleB64 = strings.TrimSpace(bundleB64)
	if bundleB64 == "" {
		return nil, nil, fmt.Errorf("netlab topology bundle is empty")
	}
	// Defensive cap: Kubernetes object size limit is ~1MiB; base64 expands.
	if len(bundleB64) > 900_000 {
		return nil, nil, fmt.Errorf("netlab topology bundle too large for in-cluster generator (%d bytes base64)", len(bundleB64))
	}
	if _, err := base64.StdEncoding.DecodeString(bundleB64); err != nil {
		return nil, nil, fmt.Errorf("invalid netlab topology bundle encoding: %w", err)
	}

	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return nil, nil, err
	}
	// The generator runs in the workspace namespace and pulls its image from GHCR.
	// Ensure the image pull secret exists in the workspace namespace before creating the Job.
	if err := kubeEnsureNamespaceImagePullSecret(ctx, ns, strings.TrimSpace(e.cfg.ImagePullSecretName), strings.TrimSpace(e.cfg.ImagePullSecretNamespace)); err != nil {
		return nil, nil, err
	}

	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}

	bundleCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-bundle", topologyName), "c9s-bundle")
	if err := kubeUpsertConfigMap(ctx, ns, bundleCM, map[string]string{
		"bundle.b64": bundleB64,
	}, labels); err != nil {
		return nil, nil, err
	}
	defer func() {
		_, _ = kubeDeleteConfigMap(context.Background(), ns, bundleCM)
	}()

	// Ensure the generator SA has permissions to create/patch ConfigMaps in the workspace namespace.
	const saName = "skyforge-netlab-generator"
	const roleName = "skyforge-netlab-generator"
	const rbName = "skyforge-netlab-generator"
	if err := kubeUpsertServiceAccount(ctx, ns, saName, labels); err != nil {
		return nil, nil, err
	}
	// kubeUpsertServiceAccount doesn't include imagePullSecrets; ensure the generator SA can pull.
	secretName := strings.TrimSpace(e.cfg.ImagePullSecretName)
	if secretName == "" {
		secretName = "ghcr-pull"
	}
	if err := kubeEnsureServiceAccountImagePullSecret(ctx, ns, saName, secretName); err != nil {
		return nil, nil, err
	}
	rules := []map[string]any{
		{
			"apiGroups": []string{""},
			"resources": []string{"configmaps"},
			"verbs":     []string{"get", "list", "create", "update", "patch", "delete"},
		},
	}
	if err := kubeUpsertRole(ctx, ns, roleName, rules, labels); err != nil {
		return nil, nil, err
	}
	if err := kubeUpsertRoleBinding(ctx, ns, rbName, roleName, saName, labels); err != nil {
		return nil, nil, err
	}

	jobName := sanitizeKubeNameFallback(fmt.Sprintf("netlab-gen-%s-%d", topologyName, time.Now().Unix()%10_000), "netlab-gen")
	manifestCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-manifest", topologyName), "c9s-manifest")

	payload := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": ns,
			"labels": map[string]any{
				"app":                   "skyforge-netlab-generator",
				"skyforge-c9s-topology": topologyName,
				"skyforge-task-id":      fmt.Sprintf("%d", spec.TaskID),
			},
		},
		"spec": map[string]any{
			"backoffLimit":            0,
			"ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						"app": "skyforge-netlab-generator",
					},
				},
				"spec": map[string]any{
					"restartPolicy":      "Never",
					"serviceAccountName": saName,
					"containers": []map[string]any{
						{
							"name":            "generator",
							"image":           image,
							"imagePullPolicy": pullPolicy,
							"env": func() []map[string]any {
								genEnv := map[string]string{
								"SKYFORGE_NETLAB_BUNDLE_PATH":   "/input/bundle.b64",
								"SKYFORGE_NETLAB_TOPOLOGY_PATH": strings.TrimSpace(topologyPath),
								"SKYFORGE_C9S_NAMESPACE":        ns,
								"SKYFORGE_C9S_TOPOLOGY_NAME":    topologyName,
								"SKYFORGE_C9S_LAB_NAME":         strings.TrimSpace(spec.LabName),
								"SKYFORGE_C9S_MANIFEST_CM":      manifestCM,
								}
								if len(spec.SetOverrides) > 0 {
									genEnv["SKYFORGE_NETLAB_SET_OVERRIDES"] = strings.Join(spec.SetOverrides, "\n")
								}
								for k, v := range spec.Environment {
									kk := strings.TrimSpace(k)
									if kk == "" {
										continue
									}
									up := strings.ToUpper(kk)
									if strings.HasPrefix(up, "NETLAB_") || strings.HasPrefix(kk, "netlab_") || up == "SKYFORGE_NETLAB_SET_OVERRIDES" {
										// Prefer explicit SetOverrides over environment-provided overrides.
										if up == "SKYFORGE_NETLAB_SET_OVERRIDES" && len(spec.SetOverrides) > 0 {
											continue
										}
										genEnv[kk] = v
									}
								}
								return kubeEnvList(genEnv)
							}(),
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
		return nil, nil, err
	}
	defer func() { _ = kubeDeleteJob(context.Background(), ns, jobName) }()

	log.Infof("Netlab generator job created: %s", jobName)
	if err := kubeWaitJob(ctx, ns, jobName, log, func() bool {
		if spec.TaskID <= 0 || e == nil {
			return false
		}
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		return canceled
	}); err != nil {
		return nil, nil, err
	}

	data, ok, err := kubeGetConfigMap(ctx, ns, manifestCM)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("netlab generator did not write manifest configmap %s", manifestCM)
	}
	raw := strings.TrimSpace(data["manifest.json"])
	if raw == "" {
		return nil, nil, fmt.Errorf("netlab generator manifest is empty")
	}
	var manifest netlabC9sManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		return nil, nil, fmt.Errorf("invalid netlab generator manifest: %w", err)
	}
	clab := strings.TrimSpace(manifest.ClabYAML)
	if clab == "" {
		return nil, nil, fmt.Errorf("netlab generator manifest missing clabYAML")
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	nodeMounts := map[string][]c9sFileFromConfigMap{}

	sharedMounts := []c9sFileFromConfigMap{}
	if manifest.SharedFiles != nil {
		cmName := strings.TrimSpace(manifest.SharedFiles.ConfigMapName)
		for _, f := range manifest.SharedFiles.Files {
			key := strings.TrimSpace(f.Key)
			rel := path.Clean(strings.TrimPrefix(strings.TrimSpace(f.Rel), "/"))
			if cmName == "" || key == "" || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			mountPath := path.Join(mountRoot, "node_files", rel)
			sharedMounts = append(sharedMounts, c9sFileFromConfigMap{
				ConfigMapName: cmName,
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
	}

	startupMounts := []c9sFileFromConfigMap{}
	if manifest.StartupConfigs != nil {
		cmName := strings.TrimSpace(manifest.StartupConfigs.ConfigMapName)
		for _, f := range manifest.StartupConfigs.Files {
			key := strings.TrimSpace(f.Key)
			rel := path.Clean(strings.TrimPrefix(strings.TrimSpace(f.Rel), "/"))
			if cmName == "" || key == "" || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			mountPath := path.Join(mountRoot, "config", rel)
			startupMounts = append(startupMounts, c9sFileFromConfigMap{
				ConfigMapName: cmName,
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
	}

	for node, entry := range manifest.Nodes {
		node = strings.TrimSpace(node)
		cmName := strings.TrimSpace(entry.ConfigMapName)
		if node == "" || cmName == "" || len(entry.Files) == 0 {
			continue
		}
		mounts := make([]c9sFileFromConfigMap, 0, len(entry.Files))
		for _, f := range entry.Files {
			key := strings.TrimSpace(f.Key)
			rel := path.Clean(strings.TrimPrefix(strings.TrimSpace(f.Rel), "/"))
			if key == "" || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			mountPath := path.Join(mountRoot, "node_files", node, rel)
			mounts = append(mounts, c9sFileFromConfigMap{
				ConfigMapName: cmName,
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
		if len(mounts) == 0 {
			continue
		}
		if len(sharedMounts) > 0 {
			mounts = append(mounts, sharedMounts...)
		}
		if len(startupMounts) > 0 {
			mounts = append(mounts, startupMounts...)
		}
		nodeMounts[node] = mounts
	}

	return []byte(clab), nodeMounts, nil
}
