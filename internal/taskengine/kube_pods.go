package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type kubeOwnerReference struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type kubePod struct {
	Metadata struct {
		Name            string               `json:"name"`
		Labels          map[string]string    `json:"labels"`
		Annotations     map[string]string    `json:"annotations"`
		OwnerReferences []kubeOwnerReference `json:"ownerReferences"`
	} `json:"metadata"`
	Status struct {
		PodIP string `json:"podIP"`
		Phase string `json:"phase"`
	} `json:"status"`
}

type kubePodListFull struct {
	Items []kubePod `json:"items"`
}

func kubeListPods(ctx context.Context, ns string, labelSelector map[string]string) ([]kubePod, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return nil, fmt.Errorf("namespace is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return nil, err
	}
	listURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods", ns)
	if len(labelSelector) > 0 {
		parts := make([]string, 0, len(labelSelector))
		for k, v := range labelSelector {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "" || v == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
		if len(parts) > 0 {
			listURL = listURL + "?labelSelector=" + url.QueryEscape(strings.Join(parts, ","))
		}
	}
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
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return nil, fmt.Errorf("kube pods list failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var pods kubePodListFull
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return nil, err
	}
	return pods.Items, nil
}
