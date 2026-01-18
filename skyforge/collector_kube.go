package skyforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/rlog"
)

const (
	defaultCollectorImage = "ghcr.io/forwardnetworks/skyforge-forward-collector:latest"
)

type collectorRuntimeStatus struct {
	Namespace       string `json:"namespace"`
	DeploymentName  string `json:"deploymentName"`
	PodName         string `json:"podName,omitempty"`
	PodPhase        string `json:"podPhase,omitempty"`
	Ready           bool   `json:"ready"`
	StartTime       string `json:"startTime,omitempty"`
	LogsCommandHint string `json:"logsCommandHint,omitempty"`
}

func collectorResourceNameForUser(username string) string {
	// Kubernetes DNS label (<=63). Keep it deterministic and human-readable.
	base := strings.TrimSpace(strings.ToLower(username))
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
	if len(base) > 40 {
		base = base[:40]
	}
	return "skyforge-collector-" + base
}

func ensureCollectorDeployed(ctx context.Context, username, token string) (*collectorRuntimeStatus, error) {
	ns := kubeNamespace()
	name := collectorResourceNameForUser(username)
	labels := map[string]string{
		"app.kubernetes.io/name":      "skyforge",
		"app.kubernetes.io/component": "collector",
		"skyforge-managed":           "true",
		"skyforge-username":          strings.TrimSpace(username),
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

	// 2) Deployment
	{
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
							"skyforge-managed":           "true",
						},
						"annotations": map[string]string{
							"skyforge/restartedAt": time.Now().UTC().Format(time.RFC3339Nano),
						},
					},
					"spec": map[string]any{
						"serviceAccountName": "default",
						"containers": []any{
							map[string]any{
								"name":            "collector",
								"image":           defaultCollectorImage,
								"imagePullPolicy": "IfNotPresent",
								"env": []any{
									map[string]any{
										"name": "TOKEN",
										"valueFrom": map[string]any{
											"secretKeyRef": map[string]any{
												"name": name,
												"key":  "TOKEN",
											},
										},
									},
								},
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
			patchBody, _ := json.Marshal(map[string]any{
				"metadata": map[string]any{"labels": labels},
				"spec": map[string]any{
					"replicas": 1,
					"template": map[string]any{
						"metadata": map[string]any{
							"annotations": map[string]string{
								"skyforge/restartedAt": time.Now().UTC().Format(time.RFC3339Nano),
							},
						},
						"spec": map[string]any{
							"serviceAccountName": "default",
							"containers": []any{
								map[string]any{
									"name":            "collector",
									"image":           defaultCollectorImage,
									"imagePullPolicy": "IfNotPresent",
									"env": []any{
										map[string]any{
											"name": "TOKEN",
											"valueFrom": map[string]any{
												"secretKeyRef": map[string]any{
													"name": name,
													"key":  "TOKEN",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			})
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
	st, err := getCollectorRuntimeStatus(ctx, username)
	if err != nil {
		rlog.Debug("collector runtime status failed", "err", err)
		return &collectorRuntimeStatus{
			Namespace:      ns,
			DeploymentName: name,
		}, nil
	}
	return st, nil
}

func getCollectorRuntimeStatus(ctx context.Context, username string) (*collectorRuntimeStatus, error) {
	ns := kubeNamespace()
	name := collectorResourceNameForUser(username)
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
					Name  string `json:"name"`
					Ready bool   `json:"ready"`
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
			break
		}
	}
	out.Ready = ready
	return out, nil
}

func deleteCollectorResources(ctx context.Context, username string) error {
	ns := kubeNamespace()
	name := collectorResourceNameForUser(username)
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
