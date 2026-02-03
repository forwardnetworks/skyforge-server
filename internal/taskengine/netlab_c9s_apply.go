package taskengine

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const defaultNetlabC9sApplierImage = "ghcr.io/forwardnetworks/skyforge-netlab-applier:latest"

func (e *Engine) runNetlabC9sApplierJob(
	ctx context.Context,
	ns, topologyName string,
	log Logger,
) error {
	if log == nil {
		log = noopLogger{}
	}
	if e == nil {
		return fmt.Errorf("engine unavailable")
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" {
		return fmt.Errorf("namespace and topologyName are required")
	}

	image := strings.TrimSpace(e.cfg.NetlabApplierImage)
	if image == "" {
		image = defaultNetlabC9sApplierImage
		log.Infof("Netlab applier image not configured; defaulting to %s", image)
	}
	pullPolicy := strings.TrimSpace(e.cfg.NetlabApplierPullPolicy)
	if pullPolicy == "" {
		pullPolicy = "IfNotPresent"
	}

	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return err
	}
	if err := kubeEnsureNamespaceImagePullSecret(ctx, ns, strings.TrimSpace(e.cfg.ImagePullSecretName), strings.TrimSpace(e.cfg.ImagePullSecretNamespace)); err != nil {
		return err
	}

	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}

	const saName = "skyforge-netlab-applier"
	const roleName = "skyforge-netlab-applier"
	const rbName = "skyforge-netlab-applier"

	if err := kubeUpsertServiceAccount(ctx, ns, saName, labels); err != nil {
		return err
	}
	secretName := strings.TrimSpace(e.cfg.ImagePullSecretName)
	if secretName == "" {
		secretName = "ghcr-pull"
	}
	if err := kubeEnsureServiceAccountImagePullSecret(ctx, ns, saName, secretName); err != nil {
		return err
	}

	rules := []map[string]any{
		{
			"apiGroups": []string{""},
			"resources": []string{"configmaps"},
			"verbs":     []string{"get", "list"},
		},
	}
	if err := kubeUpsertRole(ctx, ns, roleName, rules, labels); err != nil {
		return err
	}
	if err := kubeUpsertRoleBinding(ctx, ns, rbName, roleName, saName, labels); err != nil {
		return err
	}

	jobName := sanitizeKubeNameFallback(fmt.Sprintf("netlab-apply-%s-%d", topologyName, time.Now().Unix()%10_000), "netlab-apply")
	manifestCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-manifest", topologyName), "c9s-manifest")
	nameMapCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-name-map", topologyName), "c9s-name-map")

	payload := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": ns,
			"labels": map[string]any{
				"app":                   "skyforge-netlab-applier",
				"skyforge-c9s-topology": topologyName,
			},
		},
		"spec": map[string]any{
			"backoffLimit":            0,
			"ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						"app": "skyforge-netlab-applier",
					},
				},
				"spec": map[string]any{
					"restartPolicy":      "Never",
					"serviceAccountName": saName,
					"containers": []map[string]any{
						{
							"name":            "applier",
							"image":           image,
							"imagePullPolicy": pullPolicy,
							"env": kubeEnvList(map[string]string{
								"SKYFORGE_C9S_NAMESPACE":     ns,
								"SKYFORGE_C9S_TOPOLOGY_NAME": topologyName,
								"SKYFORGE_C9S_MANIFEST_CM":   manifestCM,
								"SKYFORGE_C9S_NAME_MAP_CM":   nameMapCM,
							}),
							"volumeMounts": []map[string]any{
								{"name": "work", "mountPath": "/work"},
							},
						},
					},
					"volumes": []map[string]any{
						{
							"name": "work",
							"emptyDir": map[string]any{
								"sizeLimit": "4Gi",
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
		if jobSucceeded {
			_ = kubeDeleteJob(context.Background(), ns, jobName)
		}
	}()
	log.Infof("Netlab applier job created: %s", jobName)
	if err := kubeWaitJob(ctx, ns, jobName, log, nil); err != nil {
		return err
	}
	jobSucceeded = true
	return nil
}
