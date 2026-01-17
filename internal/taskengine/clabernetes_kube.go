package taskengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type kubeClabernetesTopology struct {
	Status struct {
		TopologyReady bool `json:"topologyReady"`
	} `json:"status"`
}

type kubeConfigMapList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

type kubeConfigMap struct {
	Data map[string]string `json:"data"`
}

func kubeEnsureNamespace(ctx context.Context, ns string) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	getURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s", ns)
	getReq, err := kubeRequest(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return err
	}
	getResp, err := client.Do(getReq)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(getResp.Body, 4<<10))
	getResp.Body.Close()
	switch getResp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
	default:
		return fmt.Errorf("kube namespace get failed: %s", getResp.Status)
	}

	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name": ns,
			"labels": map[string]any{
				"skyforge-managed": "true",
			},
		},
	}
	body, _ := json.Marshal(payload)
	createURL := "https://kubernetes.default.svc/api/v1/namespaces"
	createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(createReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("kube namespace create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeEnsureNamespaceImagePullSecret(ctx context.Context, ns string) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	secretName := strings.TrimSpace(os.Getenv("SKYFORGE_IMAGE_PULL_SECRET_NAME"))
	if secretName == "" {
		secretName = "ghcr-pull"
	}
	srcNS := strings.TrimSpace(os.Getenv("SKYFORGE_IMAGE_PULL_SECRET_NAMESPACE"))
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
	return kubePatchDefaultServiceAccountImagePullSecret(ctx, ns, secretName)
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

func kubePatchDefaultServiceAccountImagePullSecret(ctx context.Context, ns, secretName string) error {
	ns = strings.TrimSpace(ns)
	secretName = strings.TrimSpace(secretName)
	if ns == "" || secretName == "" {
		return fmt.Errorf("namespace and secret name are required")
	}

	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}

	var sa map[string]any
	for attempt := 0; attempt < 20; attempt++ {
		url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts/default", ns)
		req, err := kubeRequest(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			time.Sleep(250 * time.Millisecond)
			continue
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
		break
	}
	if sa == nil {
		return fmt.Errorf("kube serviceaccount default not found: %s", ns)
	}

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
	updateURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts/default", ns)
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
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return fmt.Errorf("namespace and configmap name are required")
	}
	if data == nil {
		data = map[string]string{}
	}
	if labels == nil {
		labels = map[string]string{}
	}
	labels["skyforge-managed"] = "true"

	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels":    labels,
		},
		"data": data,
	}
	body, _ := json.Marshal(payload)

	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}

	createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", ns)
	createReq, err := kubeRequest(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(createReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	if resp.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube configmap create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	updateURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s", ns, name)
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
		return fmt.Errorf("kube configmap update failed: %s: %s", updateResp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeDeleteConfigMap(ctx context.Context, ns, name string) (bool, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return false, fmt.Errorf("namespace and configmap name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return false, err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s?propagationPolicy=Background", ns, name)
	req, err := kubeRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return false, fmt.Errorf("kube configmap delete failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return true, nil
}

func kubeDeleteConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return 0, fmt.Errorf("namespace is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return 0, err
	}
	var parts []string
	for k, v := range selector {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	q := ""
	if len(parts) > 0 {
		q = url.QueryEscape(strings.Join(parts, ","))
	}
	listURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", ns)
	if q != "" {
		listURL = listURL + "?labelSelector=" + q
	}
	req, err := kubeRequest(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return 0, fmt.Errorf("kube configmap list failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var list kubeConfigMapList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return 0, err
	}
	deleted := 0
	for _, item := range list.Items {
		name := strings.TrimSpace(item.Metadata.Name)
		if name == "" {
			continue
		}
		ok, err := kubeDeleteConfigMap(ctx, ns, name)
		if err != nil {
			return deleted, err
		}
		if ok {
			deleted++
		}
	}
	return deleted, nil
}

func kubeCountConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return 0, fmt.Errorf("namespace is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return 0, err
	}
	var parts []string
	for k, v := range selector {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	q := ""
	if len(parts) > 0 {
		q = url.QueryEscape(strings.Join(parts, ","))
	}
	listURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", ns)
	if q != "" {
		listURL = listURL + "?labelSelector=" + q
	}
	req, err := kubeRequest(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return 0, fmt.Errorf("kube configmap list failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var list kubeConfigMapList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return 0, err
	}
	return len(list.Items), nil
}

func kubeCreateClabernetesTopology(ctx context.Context, ns string, payload map[string]any) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/clabernetes.containerlab.dev/v1alpha1/namespaces/%s/topologies", ns)
	req, err := kubeRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube topology create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeDeleteClabernetesTopology(ctx context.Context, ns, name string) (bool, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return false, fmt.Errorf("namespace and topology name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return false, err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/clabernetes.containerlab.dev/v1alpha1/namespaces/%s/topologies/%s?propagationPolicy=Background", ns, name)
	req, err := kubeRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return false, fmt.Errorf("kube topology delete failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return true, nil
}

func kubeGetClabernetesTopology(ctx context.Context, ns, name string) (*kubeClabernetesTopology, int, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return nil, 0, fmt.Errorf("namespace and topology name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, 0, err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/clabernetes.containerlab.dev/v1alpha1/namespaces/%s/topologies/%s", ns, name)
	req, err := kubeRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	if status == http.StatusNotFound {
		return nil, status, nil
	}
	if status < 200 || status >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return nil, status, fmt.Errorf("kube topology get failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var topo kubeClabernetesTopology
	if err := json.NewDecoder(resp.Body).Decode(&topo); err != nil {
		return nil, status, err
	}
	return &topo, status, nil
}
