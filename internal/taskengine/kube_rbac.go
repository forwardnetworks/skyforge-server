package taskengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func kubeUpsertServiceAccount(ctx context.Context, ns, name string, labels map[string]string) error {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return fmt.Errorf("namespace and serviceaccount name are required")
	}
	if labels == nil {
		labels = map[string]string{}
	}
	labels["skyforge-managed"] = "true"

	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels":    labels,
		},
	}
	body, _ := json.Marshal(payload)

	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	createURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts", ns)
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
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube serviceaccount create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	updateURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/serviceaccounts/%s", ns, name)
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

func kubeUpsertRole(ctx context.Context, ns, name string, rules []map[string]any, labels map[string]string) error {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return fmt.Errorf("namespace and role name are required")
	}
	if labels == nil {
		labels = map[string]string{}
	}
	labels["skyforge-managed"] = "true"

	payload := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels":    labels,
		},
		"rules": rules,
	}
	body, _ := json.Marshal(payload)

	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	createURL := fmt.Sprintf("https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/namespaces/%s/roles", ns)
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
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube role create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	updateURL := fmt.Sprintf("https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/namespaces/%s/roles/%s", ns, name)
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
		return fmt.Errorf("kube role update failed: %s: %s", updateResp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeUpsertRoleBinding(ctx context.Context, ns, name string, roleName, serviceAccountName string, labels map[string]string) error {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	roleName = strings.TrimSpace(roleName)
	serviceAccountName = strings.TrimSpace(serviceAccountName)
	if ns == "" || name == "" || roleName == "" || serviceAccountName == "" {
		return fmt.Errorf("namespace, name, roleName, and serviceAccountName are required")
	}
	if labels == nil {
		labels = map[string]string{}
	}
	labels["skyforge-managed"] = "true"

	payload := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels":    labels,
		},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "Role",
			"name":     roleName,
		},
		"subjects": []map[string]any{
			{
				"kind":      "ServiceAccount",
				"name":      serviceAccountName,
				"namespace": ns,
			},
		},
	}
	body, _ := json.Marshal(payload)

	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	createURL := fmt.Sprintf("https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings", ns)
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
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube rolebinding create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	updateURL := fmt.Sprintf("https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings/%s", ns, name)
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
		return fmt.Errorf("kube rolebinding update failed: %s: %s", updateResp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
