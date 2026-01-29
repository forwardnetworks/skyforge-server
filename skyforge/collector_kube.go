package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encore.dev/rlog"
)

type collectorRuntimeStatus struct {
	Namespace       string `json:"namespace"`
	DeploymentName  string `json:"deploymentName"`
	PodName         string `json:"podName,omitempty"`
	PodPhase        string `json:"podPhase,omitempty"`
	Ready           bool   `json:"ready"`
	RestartCount    int32  `json:"restartCount,omitempty"`
	LastExitCode    int32  `json:"lastExitCode,omitempty"`
	LastReason      string `json:"lastReason,omitempty"`
	LastFinishedAt  string `json:"lastFinishedAt,omitempty"`
	StartTime       string `json:"startTime,omitempty"`
	Image           string `json:"image,omitempty"`
	ImageID         string `json:"imageId,omitempty"`
	RemoteDigest    string `json:"remoteDigest,omitempty"`
	UpdateAvailable bool   `json:"updateAvailable,omitempty"`
	UpdateStatus    string `json:"updateStatus,omitempty"`
	LogsCommandHint string `json:"logsCommandHint,omitempty"`
}

var ghcrImageRe = regexp.MustCompile(`^ghcr\.io/([^/]+)/([^:]+):(.+)$`)

func sanitizeKubeDNSLabelPart(value string, maxLen int) string {
	base := strings.TrimSpace(strings.ToLower(value))
	base = strings.ReplaceAll(base, "@", "-")
	base = strings.ReplaceAll(base, ".", "-")
	base = strings.ReplaceAll(base, " ", "-")
	base = strings.ReplaceAll(base, "_", "-")
	base = strings.ReplaceAll(base, "/", "-")
	base = strings.ReplaceAll(base, ":", "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "user"
	}
	if maxLen > 0 && len(base) > maxLen {
		base = base[:maxLen]
	}
	return base
}

func collectorResourceNameForUser(username string) string {
	// Kubernetes DNS label (<=63). Keep it deterministic and human-readable.
	base := sanitizeKubeDNSLabelPart(username, 40)
	return "skyforge-collector-" + base
}

func collectorResourceNameForUserCollector(username, collectorID string) string {
	collectorID = strings.TrimSpace(collectorID)
	collectorID = strings.ReplaceAll(collectorID, "-", "")
	collectorID = strings.ToLower(collectorID)
	if len(collectorID) > 8 {
		collectorID = collectorID[:8]
	}
	if collectorID == "" {
		collectorID = "c"
	}
	// "skyforge-collector-" + base + "-" + suffix must fit in 63 chars.
	// len("skyforge-collector-") == 17, plus "-" + 8 => 26, leaving 37 chars.
	base := sanitizeKubeDNSLabelPart(username, 32)
	return "skyforge-collector-" + base + "-" + collectorID
}

func ensureCollectorDeployed(ctx context.Context, cfg Config, username, token, forwardBaseURL string, skipTLSVerify bool) (*collectorRuntimeStatus, error) {
	return ensureCollectorDeployedForName(ctx, cfg, username, collectorResourceNameForUser(username), token, forwardBaseURL, skipTLSVerify)
}

func ensureCollectorDeployedForName(ctx context.Context, cfg Config, username, deploymentName, token, forwardBaseURL string, skipTLSVerify bool) (*collectorRuntimeStatus, error) {
	if !cfg.Features.ForwardEnabled {
		return &collectorRuntimeStatus{
			Namespace:       kubeNamespace(),
			DeploymentName:  strings.TrimSpace(deploymentName),
			UpdateStatus:    "disabled",
			LogsCommandHint: fmt.Sprintf("kubectl -n %s logs deploy/%s -f", kubeNamespace(), strings.TrimSpace(deploymentName)),
		}, nil
	}
	collectorImage := strings.TrimSpace(cfg.ForwardCollectorImage)
	if collectorImage == "" {
		// Explicitly do not deploy anything if the collector image isn't configured.
		// This avoids a broken UX when the cluster cannot pull the image.
		return &collectorRuntimeStatus{
			Namespace:       kubeNamespace(),
			DeploymentName:  strings.TrimSpace(deploymentName),
			UpdateStatus:    "not_configured",
			LogsCommandHint: fmt.Sprintf("kubectl -n %s logs deploy/%s -f", kubeNamespace(), strings.TrimSpace(deploymentName)),
		}, nil
	}
	collectorPullPolicy := strings.TrimSpace(cfg.ForwardCollectorPullPolicy)
	if collectorPullPolicy == "" {
		collectorPullPolicy = "IfNotPresent"
	}
	collectorHeapSizeGB := cfg.ForwardCollectorHeapSizeGB

	ns := kubeNamespace()
	name := strings.TrimSpace(deploymentName)
	if name == "" {
		name = collectorResourceNameForUser(username)
	}
	dataPVCName := name + "-data"
	configName := name + "-cfg"
	labels := map[string]string{
		"app.kubernetes.io/name":      "skyforge",
		"app.kubernetes.io/component": "collector",
		"skyforge-managed":            "true",
		"skyforge-username":           strings.TrimSpace(username),
		"skyforge-collector-name":     name,
	}

	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}

	// 1) Secret with TOKEN
	{
		payload := map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
				"labels":    labels,
			},
			"type": "Opaque",
			"stringData": map[string]string{
				"TOKEN": strings.TrimSpace(token),
			},
		}
		body, _ := json.Marshal(payload)

		createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets", url.PathEscape(ns))
		createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		createReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(createReq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
			return nil, fmt.Errorf("kube secret create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
		}
		if resp.StatusCode == http.StatusConflict {
			patchBody, _ := json.Marshal(map[string]any{
				"metadata": map[string]any{"labels": labels},
				"stringData": map[string]string{
					"TOKEN": strings.TrimSpace(token),
				},
			})
			patchURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets/%s", url.PathEscape(ns), url.PathEscape(name))
			patchReq, err := kubeRequest(ctx, http.MethodPatch, patchURL, bytes.NewReader(patchBody))
			if err != nil {
				return nil, err
			}
			patchReq.Header.Set("Content-Type", "application/strategic-merge-patch+json")
			patchResp, err := client.Do(patchReq)
			if err != nil {
				return nil, err
			}
			defer patchResp.Body.Close()
			if patchResp.StatusCode < 200 || patchResp.StatusCode >= 300 {
				data, _ := io.ReadAll(io.LimitReader(patchResp.Body, 32<<10))
				return nil, fmt.Errorf("kube secret patch failed: %s: %s", patchResp.Status, strings.TrimSpace(string(data)))
			}
		}
	}

	// 1b) ConfigMap with fwd.properties (overrides the baked-in fwd-appserver URL in the
	// Forward Enterprise collector image).
	{
		baseURL := strings.TrimSpace(forwardBaseURL)
		if baseURL == "" {
			baseURL = "https://fwd.app"
		}
		fwdProps := renderCollectorFwdProperties(baseURL, skipTLSVerify, token)
		payload := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      configName,
				"namespace": ns,
				"labels":    labels,
			},
			"data": map[string]string{
				"fwd.properties": fwdProps,
			},
		}
		body, _ := json.Marshal(payload)

		createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", url.PathEscape(ns))
		createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		createReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(createReq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
			return nil, fmt.Errorf("kube configmap create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
		}
		if resp.StatusCode == http.StatusConflict {
			patchBody, _ := json.Marshal(map[string]any{
				"metadata": map[string]any{"labels": labels},
				"data": map[string]string{
					"fwd.properties": fwdProps,
				},
			})
			patchURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s", url.PathEscape(ns), url.PathEscape(configName))
			patchReq, err := kubeRequest(ctx, http.MethodPatch, patchURL, bytes.NewReader(patchBody))
			if err != nil {
				return nil, err
			}
			patchReq.Header.Set("Content-Type", "application/strategic-merge-patch+json")
			patchResp, err := client.Do(patchReq)
			if err != nil {
				return nil, err
			}
			defer patchResp.Body.Close()
			if patchResp.StatusCode < 200 || patchResp.StatusCode >= 300 {
				data, _ := io.ReadAll(io.LimitReader(patchResp.Body, 32<<10))
				return nil, fmt.Errorf("kube configmap patch failed: %s: %s", patchResp.Status, strings.TrimSpace(string(data)))
			}
		}
	}

	// 2) Persistent data volume (stores customer_key.pb so collector restarts/upgrades
	// do not require re-entering secrets).
	{
		payload := map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":      dataPVCName,
				"namespace": ns,
				"labels":    labels,
			},
			"spec": map[string]any{
				"accessModes": []string{"ReadWriteOnce"},
				"resources": map[string]any{
					"requests": map[string]string{
						// Small, but enough for certs/keys and local state.
						"storage": "1Gi",
					},
				},
			},
		}
		body, _ := json.Marshal(payload)

		createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/persistentvolumeclaims", url.PathEscape(ns))
		pvcURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/persistentvolumeclaims/%s", url.PathEscape(ns), url.PathEscape(dataPVCName))
		patchBody, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": labels}})

		// Deprovisioning deletes the PVC; if a user reprovisions quickly, the PVC
		// might still exist but be terminating (or disappear between calls). Treat
		// conflict as a signal to verify the PVC and wait/retry as needed.
		waitUntil := time.Now().Add(2 * time.Minute)
		for {
			pvcReady := false
			createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
			if err != nil {
				return nil, err
			}
			createReq.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(createReq)
			if err != nil {
				return nil, err
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
			resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusCreated:
				// Fresh PVC.
				pvcReady = true
			case http.StatusConflict:
				// The PVC name exists. Confirm it isn't deleting.
				getReq, err := kubeRequest(ctx, http.MethodGet, pvcURL, nil)
				if err != nil {
					return nil, err
				}
				getResp, err := client.Do(getReq)
				if err != nil {
					return nil, err
				}
				getData, _ := io.ReadAll(io.LimitReader(getResp.Body, 32<<10))
				getResp.Body.Close()
				if getResp.StatusCode == http.StatusNotFound {
					// PVC disappeared after we got a conflict. Retry create.
					continue
				}
				if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
					return nil, fmt.Errorf("kube pvc get failed: %s: %s", getResp.Status, strings.TrimSpace(string(getData)))
				}
				var pvc struct {
					Metadata struct {
						DeletionTimestamp *string `json:"deletionTimestamp"`
					} `json:"metadata"`
				}
				if err := json.Unmarshal(getData, &pvc); err != nil {
					return nil, fmt.Errorf("kube pvc get parse failed: %w", err)
				}
				if pvc.Metadata.DeletionTimestamp != nil && strings.TrimSpace(*pvc.Metadata.DeletionTimestamp) != "" {
					// Still terminating; wait for it to be gone, then retry create.
					if time.Now().After(waitUntil) {
						return nil, fmt.Errorf("collector data pvc %q is still deleting; retry in a moment", dataPVCName)
					}
					rlog.Info("collector data pvc deleting; waiting", "pvc", dataPVCName)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(2 * time.Second):
					}
					continue
				}

				// PVC exists and is not deleting. Patch labels and continue.
				patchReq, err := kubeRequest(ctx, http.MethodPatch, pvcURL, bytes.NewReader(patchBody))
				if err != nil {
					return nil, err
				}
				patchReq.Header.Set("Content-Type", "application/strategic-merge-patch+json")
				patchResp, err := client.Do(patchReq)
				if err != nil {
					return nil, err
				}
				patchData, _ := io.ReadAll(io.LimitReader(patchResp.Body, 32<<10))
				patchResp.Body.Close()
				if patchResp.StatusCode < 200 || patchResp.StatusCode >= 300 {
					return nil, fmt.Errorf("kube pvc patch failed: %s: %s", patchResp.Status, strings.TrimSpace(string(patchData)))
				}
				pvcReady = true
			default:
				return nil, fmt.Errorf("kube pvc create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
			}

			if pvcReady {
				break
			}
		}
	}

	collectorEnv := []any{
		map[string]any{
			"name": "TOKEN",
			"valueFrom": map[string]any{
				"secretKeyRef": map[string]any{
					"name": name,
					"key":  "TOKEN",
				},
			},
		},
		// Required by /collector/collector.sh in the Forward Enterprise collector image.
		map[string]any{
			"name":  "LOGS_DIR",
			"value": "/scratch",
		},
		map[string]any{
			"name":  "LOGBACK_FILENAME",
			"value": "logback-client-daemon.xml",
		},
	}
	if collectorHeapSizeGB > 0 {
		collectorEnv = append(collectorEnv, map[string]any{
			"name":  "COLLECTOR_HEAP_SIZE",
			"value": strconv.Itoa(collectorHeapSizeGB),
		})
	}

	// 3) Deployment
	{
		var imagePullSecrets []any
		// imagePullSecrets must exist in the same namespace as the Pod.
		pullSecretName := strings.TrimSpace(cfg.ForwardCollectorImagePullSecretName)
		pullSecretNamespace := strings.TrimSpace(cfg.ForwardCollectorImagePullSecretNamespace)
		if pullSecretName == "" {
			pullSecretName = strings.TrimSpace(cfg.ImagePullSecretName)
		}
		if pullSecretNamespace == "" {
			pullSecretNamespace = strings.TrimSpace(cfg.ImagePullSecretNamespace)
		}
		if pullSecretName != "" && strings.TrimSpace(pullSecretNamespace) == strings.TrimSpace(ns) {
			imagePullSecrets = []any{map[string]any{"name": pullSecretName}}
		}
		payload := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
				"labels":    labels,
			},
			"spec": map[string]any{
				"replicas": 1,
				// The collector mounts a ReadWriteOnce PVC. Use Recreate to avoid
				// multi-attach issues during rolling updates.
				"strategy": map[string]any{
					"type": "Recreate",
				},
				"selector": map[string]any{
					"matchLabels": map[string]string{
						"app.kubernetes.io/name":      "skyforge",
						"app.kubernetes.io/component": "collector",
						"skyforge-collector":          name,
					},
				},
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]string{
							"app.kubernetes.io/name":      "skyforge",
							"app.kubernetes.io/component": "collector",
							"skyforge-collector":          name,
							"skyforge-managed":            "true",
							// Used by server/internal/taskengine to co-locate lab pods with the
							// user's collector (best-effort). Keep on the Pod template (not just
							// the Deployment) so it can be selected via the Pod list API.
							"skyforge-username": strings.TrimSpace(username),
						},
						"annotations": map[string]string{
							"skyforge/restartedAt": time.Now().UTC().Format(time.RFC3339Nano),
						},
					},
					"spec": map[string]any{
						"serviceAccountName": "default",
						"imagePullSecrets":   imagePullSecrets,
						"initContainers": []any{
							map[string]any{
								"name":    "init-persist-key",
								"image":   "busybox:1.36",
								"command": []string{"sh", "-c"},
								"securityContext": map[string]any{
									"runAsUser":  0,
									"runAsGroup": 0,
								},
								"args": []string{
									// Ensure the PVC root is owned by the collector uid (1000) so the daemon
									// can create/update /collector/private/customer_key.pb on first boot.
									// IMPORTANT: Do not pre-create an empty customer_key.pb. The collector
									// generates it and expects it to be non-empty; an empty file causes
									// secret encryption failures ("Empty key").
									"set -e; mkdir -p /persist; chown -R 1000:1000 /persist; chmod 700 /persist; if [ -f /persist/customer_key.pb ] && [ ! -s /persist/customer_key.pb ]; then rm -f /persist/customer_key.pb; fi; mkdir -p /generated; chown -R 1000:1000 /generated;",
								},
								"volumeMounts": []any{
									map[string]any{
										"name":      "collector-data",
										"mountPath": "/persist",
									},
									map[string]any{
										"name":      "collector-generated",
										"mountPath": "/generated",
									},
								},
							},
						},
						"volumes": []any{
							map[string]any{
								"name":     "scratch",
								"emptyDir": map[string]any{},
							},
							map[string]any{
								"name":     "collector-generated",
								"emptyDir": map[string]any{},
							},
							map[string]any{
								"name": "collector-cfg",
								"configMap": map[string]any{
									"name": configName,
								},
							},
							map[string]any{
								"name": "collector-data",
								"persistentVolumeClaim": map[string]any{
									"claimName": dataPVCName,
								},
							},
						},
						"securityContext": map[string]any{
							"runAsUser":  1000,
							"runAsGroup": 1000,
							"fsGroup":    1000,
						},
						"containers": []any{
							map[string]any{
								"name":            "collector",
								"image":           collectorImage,
								"imagePullPolicy": collectorPullPolicy,
								// The Forward collector runs connectivity checks that rely on ICMP (ping).
								// Grant NET_RAW so ping works without requiring privileged mode.
								"securityContext": map[string]any{
									// Run as root so NET_RAW is effective (Linux drops capabilities on exec
									// for non-root users unless the binary has file capabilities).
									"runAsUser":  0,
									"runAsGroup": 0,
									"capabilities": map[string]any{
										"add": []string{"NET_RAW"},
									},
								},
								"volumeMounts": []any{
									map[string]any{
										"name":      "scratch",
										"mountPath": "/scratch",
									},
									map[string]any{
										"name":      "collector-generated",
										"mountPath": "/collector/generated",
									},
									map[string]any{
										"name":      "collector-data",
										"mountPath": "/home/forward/.fwd/private",
									},
									// Forward collector docs/tools commonly reference /collector/private/customer_key.pb.
									// Mount the same PVC there so upgrades and troubleshooting workflows work as expected.
									map[string]any{
										"name":      "collector-data",
										"mountPath": "/collector/private",
									},
									map[string]any{
										"name":      "collector-cfg",
										"mountPath": "/collector/fwd.properties",
										"subPath":   "fwd.properties",
									},
								},
								"env": collectorEnv,
							},
						},
					},
				},
			},
		}

		body, _ := json.Marshal(payload)
		createURL := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments", url.PathEscape(ns))
		createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		createReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(createReq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
			return nil, fmt.Errorf("kube deployment create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
		}
		if resp.StatusCode == http.StatusConflict {
			var patchImagePullSecrets []any
			if len(imagePullSecrets) > 0 {
				patchImagePullSecrets = imagePullSecrets
			} else {
				// Ensure we clear any previous value if config changed.
				patchImagePullSecrets = []any{}
			}
			patchObj := map[string]any{
				"metadata": map[string]any{"labels": labels},
				"spec": map[string]any{
					"replicas": 1,
					"strategy": map[string]any{
						"type": "Recreate",
					},
					"template": map[string]any{
						"metadata": map[string]any{
							"annotations": map[string]string{
								"skyforge/restartedAt": time.Now().UTC().Format(time.RFC3339Nano),
							},
						},
						"spec": map[string]any{
							"serviceAccountName": "default",
							"imagePullSecrets":   patchImagePullSecrets,
							"initContainers": []any{
								map[string]any{
									"name":    "init-persist-key",
									"image":   "busybox:1.36",
									"command": []string{"sh", "-c"},
									"securityContext": map[string]any{
										"runAsUser":  0,
										"runAsGroup": 0,
									},
									"args": []string{
										"set -e; mkdir -p /persist; chown -R 1000:1000 /persist; chmod 700 /persist; if [ -f /persist/customer_key.pb ] && [ ! -s /persist/customer_key.pb ]; then rm -f /persist/customer_key.pb; fi; mkdir -p /generated; chown -R 1000:1000 /generated;",
									},
									"volumeMounts": []any{
										map[string]any{
											"name":      "collector-data",
											"mountPath": "/persist",
										},
										map[string]any{
											"name":      "collector-generated",
											"mountPath": "/generated",
										},
									},
								},
							},
							"volumes": []any{
								map[string]any{
									"name":     "scratch",
									"emptyDir": map[string]any{},
								},
								map[string]any{
									"name":     "collector-generated",
									"emptyDir": map[string]any{},
								},
								map[string]any{
									"name": "collector-cfg",
									"configMap": map[string]any{
										"name": configName,
									},
								},
								map[string]any{
									"name": "collector-data",
									"persistentVolumeClaim": map[string]any{
										"claimName": dataPVCName,
									},
								},
							},
							"securityContext": map[string]any{
								"runAsUser":  1000,
								"runAsGroup": 1000,
								"fsGroup":    1000,
							},
							"containers": []any{
								map[string]any{
									"name":            "collector",
									"image":           collectorImage,
									"imagePullPolicy": collectorPullPolicy,
									"securityContext": map[string]any{
										"runAsUser":  0,
										"runAsGroup": 0,
										"capabilities": map[string]any{
											"add": []string{"NET_RAW"},
										},
									},
									"volumeMounts": []any{
										map[string]any{
											"name":      "scratch",
											"mountPath": "/scratch",
										},
										map[string]any{
											"name":      "collector-generated",
											"mountPath": "/collector/generated",
										},
										map[string]any{
											"name":      "collector-data",
											"mountPath": "/home/forward/.fwd/private",
										},
										map[string]any{
											"name":      "collector-data",
											"mountPath": "/collector/private",
										},
										map[string]any{
											"name":      "collector-cfg",
											"mountPath": "/collector/fwd.properties",
											"subPath":   "fwd.properties",
										},
									},
									"env": collectorEnv,
								},
							},
						},
					},
				},
			}
			patchBody, _ := json.Marshal(patchObj)
			patchURL := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments/%s", url.PathEscape(ns), url.PathEscape(name))
			patchReq, err := kubeRequest(ctx, http.MethodPatch, patchURL, bytes.NewReader(patchBody))
			if err != nil {
				return nil, err
			}
			patchReq.Header.Set("Content-Type", "application/strategic-merge-patch+json")
			patchResp, err := client.Do(patchReq)
			if err != nil {
				return nil, err
			}
			defer patchResp.Body.Close()
			if patchResp.StatusCode < 200 || patchResp.StatusCode >= 300 {
				data, _ := io.ReadAll(io.LimitReader(patchResp.Body, 32<<10))
				return nil, fmt.Errorf("kube deployment patch failed: %s: %s", patchResp.Status, strings.TrimSpace(string(data)))
			}
		}
	}

	// Best-effort runtime status
	st, err := getCollectorRuntimeStatusByName(ctx, name)
	if err != nil {
		rlog.Debug("collector runtime status failed", "err", err)
		return &collectorRuntimeStatus{
			Namespace:      ns,
			DeploymentName: name,
		}, nil
	}
	return st, nil
}

func renderCollectorFwdProperties(baseURL string, skipTLSVerify bool, authorizationKey string) string {
	urlStr := strings.TrimSpace(baseURL)
	if urlStr == "" {
		urlStr = "https://fwd.app"
	}
	if !strings.Contains(urlStr, "://") {
		urlStr = "https://" + urlStr
	}
	username := ""
	password := ""
	if ak := strings.TrimSpace(authorizationKey); ak != "" {
		parts := strings.SplitN(ak, ":", 2)
		if len(parts) == 2 {
			username = strings.TrimSpace(parts[0])
			password = strings.TrimSpace(parts[1])
		}
	}
	verifySSL := "true"
	if skipTLSVerify {
		verifySSL = "false"
	}
	// Minimal config needed by the collector to reach the Forward server.
	// The Forward collector image expects username/password in fwd.properties. For
	// fwd.app we use the authorization key returned from POST /api/collectors:
	//   <collector-username>:<secret>
	return strings.TrimSpace(fmt.Sprintf(`
# Managed by Skyforge.
url = %s
username = %s
password = %s
verify_ssl_cert = %s
disable_auto_update = true
version = 1.7
`, urlStr, username, password, verifySSL)) + "\n"
}

func getCollectorRuntimeStatus(ctx context.Context, username string) (*collectorRuntimeStatus, error) {
	return getCollectorRuntimeStatusByName(ctx, collectorResourceNameForUser(username))
}

func getCollectorRuntimeStatusByName(ctx context.Context, deploymentName string) (*collectorRuntimeStatus, error) {
	ns := kubeNamespace()
	name := strings.TrimSpace(deploymentName)
	if name == "" {
		return nil, fmt.Errorf("collector deployment name not specified")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}
	qs := url.Values{}
	qs.Set("labelSelector", "skyforge-collector="+name)
	listURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods?%s", url.PathEscape(ns), qs.Encode())
	req, err := kubeRequest(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return nil, fmt.Errorf("kube list pods failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var payload struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Name    string `json:"name"`
					Ready   bool   `json:"ready"`
					Image   string `json:"image"`
					ImageID string `json:"imageID"`
					Restart int32  `json:"restartCount"`
					State   struct {
						Terminated *struct {
							ExitCode   int32  `json:"exitCode"`
							Reason     string `json:"reason"`
							FinishedAt string `json:"finishedAt"`
						} `json:"terminated,omitempty"`
					} `json:"state,omitempty"`
					LastState struct {
						Terminated *struct {
							ExitCode   int32  `json:"exitCode"`
							Reason     string `json:"reason"`
							FinishedAt string `json:"finishedAt"`
						} `json:"terminated,omitempty"`
					} `json:"lastState,omitempty"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := &collectorRuntimeStatus{
		Namespace:       ns,
		DeploymentName:  name,
		LogsCommandHint: fmt.Sprintf("kubectl -n %s logs deploy/%s -f", ns, name),
	}
	if len(payload.Items) == 0 {
		return out, nil
	}
	pod := payload.Items[0]
	out.PodName = strings.TrimSpace(pod.Metadata.Name)
	out.PodPhase = strings.TrimSpace(pod.Status.Phase)
	out.StartTime = strings.TrimSpace(pod.Metadata.CreationTimestamp)
	ready := false
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "collector" && cs.Ready {
			ready = true
		}
		if cs.Name == "collector" {
			out.Image = strings.TrimSpace(cs.Image)
			out.ImageID = strings.TrimSpace(cs.ImageID)
			out.RestartCount = cs.Restart
			if cs.State.Terminated != nil {
				out.LastExitCode = cs.State.Terminated.ExitCode
				out.LastReason = strings.TrimSpace(cs.State.Terminated.Reason)
				out.LastFinishedAt = strings.TrimSpace(cs.State.Terminated.FinishedAt)
			} else if cs.LastState.Terminated != nil {
				out.LastExitCode = cs.LastState.Terminated.ExitCode
				out.LastReason = strings.TrimSpace(cs.LastState.Terminated.Reason)
				out.LastFinishedAt = strings.TrimSpace(cs.LastState.Terminated.FinishedAt)
			}
		}
	}
	out.Ready = ready

	// Best-effort update check for ghcr.io images. If the registry is private or requires auth,
	// we return a status of "unknown" instead of failing the whole endpoint.
	if digest, status := checkGHCRTagDigest(ctx, out.Image); status != "" {
		out.RemoteDigest = digest
		out.UpdateStatus = status
		if digest != "" && strings.Contains(out.ImageID, digest) == false && strings.TrimSpace(out.ImageID) != "" {
			// If we have both digests and they don't match, consider an update available.
			out.UpdateAvailable = true
		}
	}

	return out, nil
}

func getCollectorPodLogs(ctx context.Context, namespace, podName, containerName string, tailLines int) (string, error) {
	namespace = strings.TrimSpace(namespace)
	podName = strings.TrimSpace(podName)
	containerName = strings.TrimSpace(containerName)
	if namespace == "" || podName == "" {
		return "", fmt.Errorf("pod not specified")
	}
	if tailLines <= 0 {
		tailLines = 200
	}

	client, err := kubeHTTPClient()
	if err != nil {
		return "", err
	}

	qs := url.Values{}
	if containerName != "" {
		qs.Set("container", containerName)
	}
	qs.Set("tailLines", fmt.Sprintf("%d", tailLines))
	qs.Set("timestamps", "true")
	u := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods/%s/log?%s",
		url.PathEscape(namespace), url.PathEscape(podName), qs.Encode())
	req, err := kubeRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return "", fmt.Errorf("kube logs failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return string(data), nil
}

func getCollectorClientdLog(ctx context.Context, namespace, podName string, tailLines int) (string, error) {
	namespace = strings.TrimSpace(namespace)
	podName = strings.TrimSpace(podName)
	if namespace == "" || podName == "" {
		return "", fmt.Errorf("pod not specified")
	}
	if tailLines <= 0 {
		tailLines = 200
	}
	if tailLines > 5000 {
		tailLines = 5000
	}

	kcfg, err := kubeInClusterConfig()
	if err != nil {
		return "", err
	}

	// NOTE: execPodShell uses `sh -lc`, so don't rely on bashisms like `pipefail`.
	script := fmt.Sprintf(`set -eu
if [ -f /scratch/clientd.log ]; then
  tail -n %d /scratch/clientd.log
  exit 0
fi
if [ -f /scratch/clientd_fatal.log ]; then
  tail -n %d /scratch/clientd_fatal.log
  exit 0
fi
echo "no clientd log found in /scratch"`, tailLines, tailLines)

	stdout, stderr, err := execPodShell(ctx, kcfg, namespace, podName, "collector", script)
	if err != nil {
		if strings.TrimSpace(stderr) != "" {
			return "", fmt.Errorf("collector exec failed: %w: %s", err, strings.TrimSpace(stderr))
		}
		return "", fmt.Errorf("collector exec failed: %w", err)
	}
	out := stdout
	if strings.TrimSpace(stderr) != "" {
		out = strings.TrimRight(out, "\n") + "\n" + strings.TrimSpace(stderr) + "\n"
	}
	return out, nil
}

func checkGHCRTagDigest(ctx context.Context, image string) (digest string, status string) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", ""
	}
	m := ghcrImageRe.FindStringSubmatch(image)
	if len(m) != 4 {
		return "", ""
	}
	org := m[1]
	repo := m[2]
	tag := m[3]

	reqURL := fmt.Sprintf("https://ghcr.io/v2/%s/%s/manifests/%s", url.PathEscape(org), url.PathEscape(repo), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return "", "unknown"
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "unknown"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		d := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
		if d == "" {
			return "", "unknown"
		}
		return d, "ok"
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", "unknown"
	default:
		return "", "unknown"
	}
}

func deleteCollectorResources(ctx context.Context, username string) error {
	return deleteCollectorResourcesByName(ctx, collectorResourceNameForUser(username))
}

func deleteCollectorResourcesByName(ctx context.Context, deploymentName string) error {
	ns := kubeNamespace()
	name := strings.TrimSpace(deploymentName)
	if name == "" {
		return fmt.Errorf("collector deployment name not specified")
	}
	dataPVCName := name + "-data"
	configName := name + "-cfg"
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}

	// Deployment
	{
		u := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments/%s?propagationPolicy=Background",
			url.PathEscape(ns), url.PathEscape(name))
		req, err := kubeRequest(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			return fmt.Errorf("kube delete deployment failed: %s", resp.Status)
		}
	}

	// PVC (best-effort). Keep it around if deletion fails, to avoid breaking the
	// Clear action just because storage is temporarily unavailable.
	{
		u := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/persistentvolumeclaims/%s?propagationPolicy=Background",
			url.PathEscape(ns), url.PathEscape(dataPVCName))
		req, err := kubeRequest(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			rlog.Debug("kube delete pvc failed", "status", resp.Status, "pvc", dataPVCName)
		}
	}

	// ConfigMap (best-effort).
	{
		u := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s?propagationPolicy=Background",
			url.PathEscape(ns), url.PathEscape(configName))
		req, err := kubeRequest(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			rlog.Debug("kube delete configmap failed", "status", resp.Status, "configmap", configName)
		}
	}

	// Secret
	{
		u := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets/%s?propagationPolicy=Background",
			url.PathEscape(ns), url.PathEscape(name))
		req, err := kubeRequest(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			return fmt.Errorf("kube delete secret failed: %s", resp.Status)
		}
	}

	return nil
}

func restartCollectorDeployment(ctx context.Context, username string) error {
	return restartCollectorDeploymentByName(ctx, collectorResourceNameForUser(username))
}

func restartCollectorDeploymentByName(ctx context.Context, deploymentName string) error {
	ns := kubeNamespace()
	name := strings.TrimSpace(deploymentName)
	if name == "" {
		return fmt.Errorf("collector deployment name not specified")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	patchBody, _ := json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						"skyforge/restartedAt": time.Now().UTC().Format(time.RFC3339Nano),
					},
				},
			},
		},
	})
	patchURL := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments/%s", url.PathEscape(ns), url.PathEscape(name))
	patchReq, err := kubeRequest(ctx, http.MethodPatch, patchURL, bytes.NewReader(patchBody))
	if err != nil {
		return err
	}
	patchReq.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	resp, err := client.Do(patchReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("collector is not deployed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("kube deployment restart failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
