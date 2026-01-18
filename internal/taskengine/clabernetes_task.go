package taskengine

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

func envBool(env map[string]string, key string, def bool) bool {
	if env == nil {
		return def
	}
	raw, ok := env[key]
	if !ok {
		return def
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return b
}

func envString(env map[string]string, key string) string {
	if env == nil {
		return ""
	}
	raw, ok := env[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(raw)
}

type c9sFileFromConfigMap struct {
	ConfigMapName string `json:"configMapName,omitempty"`
	ConfigMapPath string `json:"configMapPath,omitempty"`
	FilePath      string `json:"filePath,omitempty"`
	Mode          string `json:"mode,omitempty"` // read|execute
}

type clabernetesTaskSpec struct {
	Action             string                            `json:"action,omitempty"`
	Namespace          string                            `json:"namespace,omitempty"`
	TopologyName       string                            `json:"topologyName,omitempty"`
	LabName            string                            `json:"labName,omitempty"`
	Template           string                            `json:"template,omitempty"`
	TopologyYAML       string                            `json:"topologyYAML,omitempty"`
	Environment        map[string]string                 `json:"environment,omitempty"`
	FilesFromConfigMap map[string][]c9sFileFromConfigMap `json:"filesFromConfigMap,omitempty"`
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

func (e *Engine) dispatchClabernetesTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn clabernetesTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	runSpec := clabernetesRunSpec{
		TaskID:             task.ID,
		Action:             strings.TrimSpace(specIn.Action),
		Namespace:          strings.TrimSpace(specIn.Namespace),
		TopologyName:       strings.TrimSpace(specIn.TopologyName),
		LabName:            strings.TrimSpace(specIn.LabName),
		Template:           strings.TrimSpace(specIn.Template),
		TopologyYAML:       strings.TrimSpace(specIn.TopologyYAML),
		Environment:        specIn.Environment,
		FilesFromConfigMap: specIn.FilesFromConfigMap,
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "clabernetes."+action, func() error {
		return e.runClabernetesTask(ctx, runSpec, log)
	})
}

func (e *Engine) runClabernetesTask(ctx context.Context, spec clabernetesRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
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

	switch strings.ToLower(strings.TrimSpace(spec.Action)) {
	case "deploy":
		log.Infof("Clabernetes deploy: namespace=%s topology=%s", ns, name)
		if err := kubeEnsureNamespace(ctx, ns); err != nil {
			return err
		}
		if err := kubeEnsureNamespaceImagePullSecret(ctx, ns); err != nil {
			return err
		}
		if _, err := kubeDeleteClabernetesTopology(ctx, ns, name); err != nil {
			return err
		}
		if len(spec.FilesFromConfigMap) > 0 {
			log.Infof("Clabernetes file mounts: nodes=%d", len(spec.FilesFromConfigMap))
		}
		connectivity := strings.ToLower(envString(spec.Environment, "SKYFORGE_CLABERNETES_CONNECTIVITY"))
		nativeMode := envBool(spec.Environment, "SKYFORGE_CLABERNETES_NATIVE_MODE", true)
		hostNetwork := envBool(spec.Environment, "SKYFORGE_CLABERNETES_HOST_NETWORK", false)
		// Ensure clabernetes launcher pods can pull private images (launcher/NOS) by wiring the
		// namespace pull secret into the topology service account via spec.imagePull.pullSecrets.
		secretName := strings.TrimSpace(os.Getenv("SKYFORGE_IMAGE_PULL_SECRET_NAME"))
		if secretName == "" {
			secretName = "ghcr-pull"
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
				"imagePull": map[string]any{
					"pullSecrets": []any{secretName},
				},
			},
		}

		if spec.TopologyYAML != "" {
			sanitized, mapping, err := sanitizeContainerlabYAMLForClabernetes(spec.TopologyYAML)
			if err != nil {
				return err
			}
			if sanitized != "" {
				spec.TopologyYAML = sanitized
				payload["spec"].(map[string]any)["definition"].(map[string]any)["containerlab"] = spec.TopologyYAML
			}
			if len(mapping) > 0 && len(spec.FilesFromConfigMap) > 0 {
				out := map[string][]c9sFileFromConfigMap{}
				for node, mounts := range spec.FilesFromConfigMap {
					newNode := strings.TrimSpace(node)
					if mapped, ok := mapping[newNode]; ok {
						newNode = mapped
					}
					if newNode == "" {
						continue
					}
					for i := range mounts {
						// Keep file paths consistent with sanitized node names.
						for old, newName := range mapping {
							mounts[i].FilePath = strings.ReplaceAll(mounts[i].FilePath, "/node_files/"+old+"/", "/node_files/"+newName+"/")
						}
					}
					out[newNode] = mounts
				}
				spec.FilesFromConfigMap = out
			}
		}
		if connectivity != "" {
			payload["spec"].(map[string]any)["connectivity"] = connectivity
		}

		deployment := map[string]any{
			"nativeMode":  nativeMode,
			"hostNetwork": hostNetwork,
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
				deployment["filesFromConfigMap"] = files
			}
		}

		if len(deployment) > 0 {
			payload["spec"].(map[string]any)["deployment"] = deployment
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
					canceled, _ := e.taskCanceled(ctx, spec.TaskID)
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
					canceled, _ := e.taskCanceled(ctx, spec.TaskID)
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
