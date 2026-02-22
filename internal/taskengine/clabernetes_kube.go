package taskengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	"encore.app/internal/kubeutil"
)

type kubeClabernetesTopology = kubeutil.ClabernetesTopology

type kubeConfigMap struct {
	Data map[string]string `json:"data"`
}

func kubeEnsureNamespace(ctx context.Context, ns string) error {
	return kubeutil.EnsureNamespace(ctx, ns)
}

func kubeEnsureNamespaceImagePullSecret(ctx context.Context, ns string, secretName string, srcNS string) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	if secretName == "" {
		secretName = "ghcr-pull"
	}
	if srcNS == "" {
		srcNS = "skyforge"
	}
	if ns == srcNS {
		return nil
	}

	secret, ok, err := kubeGetSecret(ctx, srcNS, secretName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("kube image pull secret not found: %s/%s", srcNS, secretName)
	}
	if err := kubeCreateSecretIfMissing(ctx, ns, secret, map[string]string{"skyforge-managed": "true"}); err != nil {
		return err
	}

	// clabernetes "classic" (non-native) mode uses a nested docker engine in the launcher pod, and
	// docker needs a client config at /root/.docker/config.json to pull from private registries
	// like GHCR. Create a companion secret with the expected key.
	if _, err := kubeEnsureDockerConfigSecretFromPullSecret(ctx, ns, secretName, secret); err != nil {
		return err
	}

	if err := kubeEnsureServiceAccountImagePullSecret(ctx, ns, "default", secretName); err != nil {
		return err
	}
	// clabernetes creates/uses this service identity for launcher pods.
	if err := kubeEnsureServiceAccountImagePullSecret(ctx, ns, "clabernetes-launcher-service-account", secretName); err != nil {
		return err
	}
	return nil
}

func kubeEnsureDockerConfigSecretFromPullSecret(ctx context.Context, ns, pullSecretName string, pullSecret map[string]any) (string, error) {
	ns = strings.TrimSpace(ns)
	pullSecretName = strings.TrimSpace(pullSecretName)
	if ns == "" || pullSecretName == "" {
		return "", fmt.Errorf("namespace and pull secret name are required")
	}
	if pullSecret == nil {
		return "", fmt.Errorf("pull secret payload is required")
	}

	// K8s docker registry secrets store the docker config JSON under `.dockerconfigjson`.
	data, _ := pullSecret["data"].(map[string]any)
	raw := ""
	if v, ok := data[".dockerconfigjson"].(string); ok {
		raw = strings.TrimSpace(v)
	}
	if raw == "" {
		return "", fmt.Errorf("pull secret %s has no .dockerconfigjson data", pullSecretName)
	}

	// Name kept stable so Skyforge can reference it in clabernetes Topology specs.
	dockerConfigSecretName := pullSecretName + "-docker-config"

	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      dockerConfigSecretName,
			"namespace": ns,
		},
		"type": "Opaque",
		"data": map[string]any{
			"config.json": raw,
		},
	}
	if err := kubeCreateSecretIfMissing(ctx, ns, payload, map[string]string{"skyforge-managed": "true"}); err != nil {
		return "", err
	}

	return dockerConfigSecretName, nil
}

func kubeGetSecret(ctx context.Context, ns, name string) (map[string]any, bool, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return nil, false, fmt.Errorf("namespace and secret name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, false, err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets/%s", ns, name)
	req, err := kubeRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return nil, false, fmt.Errorf("kube secret get failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func kubeCreateSecretIfMissing(ctx context.Context, ns string, secret map[string]any, labels map[string]string) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	if secret == nil {
		return fmt.Errorf("secret payload is required")
	}

	metadata, _ := secret["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("secret name missing in payload")
	}

	// If it already exists, nothing to do.
	_, ok, err := kubeGetSecret(ctx, ns, name)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
		},
	}
	if t, ok := secret["type"].(string); ok && strings.TrimSpace(t) != "" {
		payload["type"] = t
	}
	if data, ok := secret["data"].(map[string]any); ok && len(data) > 0 {
		payload["data"] = data
	}
	if labels != nil && len(labels) > 0 {
		payload["metadata"].(map[string]any)["labels"] = labels
	}

	body, _ := json.Marshal(payload)
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets", ns)
	req, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	return fmt.Errorf("kube secret create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
}

func kubeEnsureServiceAccountImagePullSecret(ctx context.Context, ns, saName, secretName string) error {
	ns = strings.TrimSpace(ns)
	saName = strings.TrimSpace(saName)
	secretName = strings.TrimSpace(secretName)
	if ns == "" || saName == "" || secretName == "" {
		return fmt.Errorf("namespace, service identity name, and secret name are required")
	}

	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}

	getURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts/%s", ns, neturl.PathEscape(saName))
	req, err := kubeRequest(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	var sa map[string]any
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		payload := map[string]any{
			"apiVersion": "v1",
			"kind":       "ServiceAccount",
			"metadata": map[string]any{
				"name":      saName,
				"namespace": ns,
				"labels": map[string]any{
					"skyforge-managed": "true",
				},
			},
			"imagePullSecrets": []any{map[string]any{"name": secretName}},
		}
		body, _ := json.Marshal(payload)
		createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts", ns)
		createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		createReq.Header.Set("Content-Type", "application/json")
		createResp, err := client.Do(createReq)
		if err != nil {
			return err
		}
		defer createResp.Body.Close()
		if createResp.StatusCode == http.StatusCreated || createResp.StatusCode == http.StatusConflict {
			return nil
		}
		data, _ := io.ReadAll(io.LimitReader(createResp.Body, 32<<10))
		return fmt.Errorf("kube serviceaccount create failed: %s: %s", createResp.Status, strings.TrimSpace(string(data)))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		resp.Body.Close()
		return fmt.Errorf("kube serviceaccount get failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&sa); err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	var pullSecrets []any
	if cur, ok := sa["imagePullSecrets"].([]any); ok {
		pullSecrets = cur
	}
	found := false
	for _, item := range pullSecrets {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if strings.TrimSpace(fmt.Sprint(m["name"])) == secretName {
			found = true
			break
		}
	}
	if !found {
		pullSecrets = append(pullSecrets, map[string]any{"name": secretName})
		sa["imagePullSecrets"] = pullSecrets
	}
	body, _ := json.Marshal(sa)
	updateURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts/%s", ns, neturl.PathEscape(saName))
	updateReq, err := kubeRequest(ctx, http.MethodPut, updateURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	updateReq.Header.Set("Content-Type", "application/json")
	updateResp, err := client.Do(updateReq)
	if err != nil {
		return err
	}
	defer updateResp.Body.Close()
	if updateResp.StatusCode < 200 || updateResp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(updateResp.Body, 32<<10))
		return fmt.Errorf("kube serviceaccount update failed: %s: %s", updateResp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeGetConfigMap(ctx context.Context, ns, name string) (map[string]string, bool, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return nil, false, fmt.Errorf("namespace and configmap name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, false, err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s", ns, name)
	req, err := kubeRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return nil, false, fmt.Errorf("kube configmap get failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var cm kubeConfigMap
	if err := json.NewDecoder(resp.Body).Decode(&cm); err != nil {
		return nil, false, err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	return cm.Data, true, nil
}

func kubeUpsertConfigMap(ctx context.Context, ns, name string, data map[string]string, labels map[string]string) error {
	return kubeutil.UpsertConfigMap(ctx, ns, name, data, labels)
}

func kubeDeleteConfigMap(ctx context.Context, ns, name string) (bool, error) {
	return kubeutil.DeleteConfigMap(ctx, ns, name)
}

func kubeDeleteConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	return kubeutil.DeleteConfigMapsByLabel(ctx, ns, selector)
}

func kubeLabelSelectorQuery(selector map[string]string) string {
	var parts []string
	for k, v := range selector {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	if len(parts) == 0 {
		return ""
	}
	return neturl.QueryEscape(strings.Join(parts, ","))
}

func kubeDeleteCollectionByLabel(ctx context.Context, listURL string, selector map[string]string) error {
	listURL = strings.TrimSpace(listURL)
	if listURL == "" {
		return fmt.Errorf("list URL is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	q := kubeLabelSelectorQuery(selector)
	url := listURL
	if q != "" {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url = url + sep + "labelSelector=" + q
	}
	req, err := kubeRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube delete collection failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeDeleteOrphanedClabernetesResources(ctx context.Context, ns, topologyOwner string) error {
	ns = strings.TrimSpace(ns)
	topologyOwner = strings.TrimSpace(topologyOwner)
	if ns == "" || topologyOwner == "" {
		return fmt.Errorf("namespace and topology owner are required")
	}
	selector := map[string]string{
		"clabernetes/topologyOwner": topologyOwner,
	}
	// Delete collections (fast) to avoid leaving thousands of crashloop-created ReplicaSets.
	if err := kubeDeleteCollectionByLabel(ctx, fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods?propagationPolicy=Background", ns), selector); err != nil {
		return err
	}
	if err := kubeDeleteCollectionByLabel(ctx, fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/services?propagationPolicy=Background", ns), selector); err != nil {
		return err
	}
	if err := kubeDeleteCollectionByLabel(ctx, fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/replicasets?propagationPolicy=Background", ns), selector); err != nil {
		return err
	}
	return nil
}

func kubeCountConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	return kubeutil.CountConfigMapsByLabel(ctx, ns, selector)
}

func kubeCreateClabernetesTopology(ctx context.Context, ns string, payload map[string]any) error {
	return kubeutil.CreateClabernetesTopology(ctx, ns, payload)
}

func kubeDeleteClabernetesTopology(ctx context.Context, ns, name string) (bool, error) {
	return kubeutil.DeleteClabernetesTopology(ctx, ns, name)
}

func kubeGetClabernetesTopology(ctx context.Context, ns, name string) (*kubeClabernetesTopology, int, error) {
	return kubeutil.GetClabernetesTopology(ctx, ns, name)
}
