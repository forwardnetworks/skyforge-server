package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type kubeService struct {
	Spec struct {
		ClusterIP string `json:"clusterIP"`
	} `json:"spec"`
}

func kubeGetServiceClusterIP(ctx context.Context, ns, name string) (ip string, found bool, err error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return "", false, fmt.Errorf("namespace and service name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return "", false, err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/services/%s", ns, name)
	req, err := kubeRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return "", false, fmt.Errorf("kube service get failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var svc kubeService
	if err := json.NewDecoder(resp.Body).Decode(&svc); err != nil {
		return "", false, err
	}
	ip = strings.TrimSpace(svc.Spec.ClusterIP)
	if ip == "" || strings.EqualFold(ip, "none") {
		return "", true, nil
	}
	return ip, true, nil
}

