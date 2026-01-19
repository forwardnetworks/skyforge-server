package kubeutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type ClabernetesTopology struct {
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

func EnsureNamespace(ctx context.Context, ns string) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}

	client, err := HTTPClient()
	if err != nil {
		return err
	}

	getURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s", ns)
	getReq, err := Request(ctx, http.MethodGet, getURL, nil)
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
	createReq, err := Request(ctx, http.MethodPost, createURL, bytes.NewReader(body))
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

func UpsertConfigMap(ctx context.Context, ns, name string, data map[string]string, labels map[string]string) error {
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

	client, err := HTTPClient()
	if err != nil {
		return err
	}

	createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", ns)
	createReq, err := Request(ctx, http.MethodPost, createURL, bytes.NewReader(body))
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
	updateReq, err := Request(ctx, http.MethodPut, updateURL, bytes.NewReader(body))
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

func DeleteConfigMap(ctx context.Context, ns, name string) (bool, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return false, fmt.Errorf("namespace and configmap name are required")
	}

	client, err := HTTPClient()
	if err != nil {
		return false, err
	}

	deleteURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps/%s?propagationPolicy=Background", ns, name)
	req, err := Request(ctx, http.MethodDelete, deleteURL, nil)
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

func DeleteConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return 0, fmt.Errorf("namespace is required")
	}

	client, err := HTTPClient()
	if err != nil {
		return 0, err
	}

	listURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", ns)
	if q := labelSelectorQuery(selector); q != "" {
		listURL += "?labelSelector=" + q
	}
	req, err := Request(ctx, http.MethodGet, listURL, nil)
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
		ok, err := DeleteConfigMap(ctx, ns, name)
		if err != nil {
			return deleted, err
		}
		if ok {
			deleted++
		}
	}
	return deleted, nil
}

func CountConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return 0, fmt.Errorf("namespace is required")
	}

	client, err := HTTPClient()
	if err != nil {
		return 0, err
	}

	listURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", ns)
	if q := labelSelectorQuery(selector); q != "" {
		listURL += "?labelSelector=" + q
	}
	req, err := Request(ctx, http.MethodGet, listURL, nil)
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

func CreateClabernetesTopology(ctx context.Context, ns string, payload map[string]any) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}

	client, err := HTTPClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(payload)
	topologiesURL := fmt.Sprintf("https://kubernetes.default.svc/apis/clabernetes.containerlab.dev/v1alpha1/namespaces/%s/topologies", ns)
	req, err := Request(ctx, http.MethodPost, topologiesURL, bytes.NewReader(body))
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

func DeleteClabernetesTopology(ctx context.Context, ns, name string) (bool, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return false, fmt.Errorf("namespace and topology name are required")
	}

	client, err := HTTPClient()
	if err != nil {
		return false, err
	}
	deleteURL := fmt.Sprintf("https://kubernetes.default.svc/apis/clabernetes.containerlab.dev/v1alpha1/namespaces/%s/topologies/%s?propagationPolicy=Background", ns, name)
	req, err := Request(ctx, http.MethodDelete, deleteURL, nil)
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

func GetClabernetesTopology(ctx context.Context, ns, name string) (*ClabernetesTopology, int, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return nil, 0, fmt.Errorf("namespace and topology name are required")
	}

	client, err := HTTPClient()
	if err != nil {
		return nil, 0, err
	}
	getURL := fmt.Sprintf("https://kubernetes.default.svc/apis/clabernetes.containerlab.dev/v1alpha1/namespaces/%s/topologies/%s", ns, name)
	req, err := Request(ctx, http.MethodGet, getURL, nil)
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
	var topo ClabernetesTopology
	if err := json.NewDecoder(resp.Body).Decode(&topo); err != nil {
		return nil, status, err
	}
	return &topo, status, nil
}

func labelSelectorQuery(selector map[string]string) string {
	if len(selector) == 0 {
		return ""
	}
	parts := make([]string, 0, len(selector))
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
	return url.QueryEscape(strings.Join(parts, ","))
}
