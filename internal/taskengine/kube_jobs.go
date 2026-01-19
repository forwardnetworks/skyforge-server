package taskengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type kubeJobStatus struct {
	Active    int
	Succeeded int
	Failed    int
}

func kubeEnvList(env map[string]string) []map[string]any {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		v := strings.TrimSpace(env[k])
		out = append(out, map[string]any{
			"name":  k,
			"value": v,
		})
	}
	return out
}

func kubeCreateJob(ctx context.Context, ns string, payload map[string]any) error {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return fmt.Errorf("namespace is required")
	}
	if payload == nil {
		return fmt.Errorf("job payload is required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	createURL := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs", ns)
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return fmt.Errorf("kube job create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeDeleteJob(ctx context.Context, ns, name string) error {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return fmt.Errorf("namespace and job name are required")
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	deleteURL := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs/%s", ns, url.PathEscape(name))
	deleteURL = deleteURL + "?propagationPolicy=Background"
	req, err := kubeRequest(ctx, http.MethodDelete, deleteURL, nil)
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
		return fmt.Errorf("kube job delete failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeGetJobStatus(ctx context.Context, client *http.Client, ns, name string) (kubeJobStatus, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return kubeJobStatus{}, fmt.Errorf("namespace and job name are required")
	}
	if client == nil {
		var err error
		client, err = kubeHTTPClient()
		if err != nil {
			return kubeJobStatus{}, err
		}
	}
	getURL := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs/%s", ns, url.PathEscape(name))
	req, err := kubeRequest(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return kubeJobStatus{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return kubeJobStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
		return kubeJobStatus{}, fmt.Errorf("kube job status failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var doc struct {
		Status struct {
			Active    int `json:"active"`
			Succeeded int `json:"succeeded"`
			Failed    int `json:"failed"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return kubeJobStatus{}, err
	}
	return kubeJobStatus{Active: doc.Status.Active, Succeeded: doc.Status.Succeeded, Failed: doc.Status.Failed}, nil
}

func kubeGetJobLogs(ctx context.Context, client *http.Client, ns, name string) (string, error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return "", fmt.Errorf("namespace and job name are required")
	}
	if client == nil {
		var err error
		client, err = kubeHTTPClient()
		if err != nil {
			return "", err
		}
	}
	pods, err := kubeListPods(ctx, ns, map[string]string{"job-name": name})
	if err != nil {
		return "", err
	}
	if len(pods) == 0 {
		return "", nil
	}
	podName := strings.TrimSpace(pods[0].Metadata.Name)
	if podName == "" {
		return "", nil
	}
	logURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods/%s/log", ns, url.PathEscape(podName))
	logURL = logURL + "?timestamps=true"
	req, err := kubeRequest(ctx, http.MethodGet, logURL, nil)
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
		return "", fmt.Errorf("kube job logs failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func kubeWaitJob(ctx context.Context, ns, name string, log Logger, canceled func() bool) error {
	if log == nil {
		log = noopLogger{}
	}
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	started := time.Now()
	var lastHeartbeat time.Time
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("job canceled")
		case <-ticker.C:
			if canceled != nil && canceled() {
				_ = kubeDeleteJob(context.Background(), ns, name)
				return fmt.Errorf("job canceled")
			}
			status, err := kubeGetJobStatus(ctx, client, ns, name)
			if err != nil {
				log.Errorf("Job status error: %v", err)
			}
			if time.Since(lastHeartbeat) >= 30*time.Second {
				lastHeartbeat = time.Now()
				log.Infof("Job still running (elapsed %s)", time.Since(started).Truncate(time.Second))
			}
			if status.Failed > 0 {
				lastLog, _ := kubeGetJobLogs(ctx, client, ns, name)
				return fmt.Errorf("job failed: %s", tailLines(lastLog, 40))
			}
			if status.Succeeded > 0 {
				return nil
			}
		}
	}
}

func appendJobLogs(delta string, log Logger) {
	if log == nil || strings.TrimSpace(delta) == "" {
		return
	}
	for _, line := range strings.Split(delta, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		log.Infof("%s", line)
	}
}

func tailLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

