package taskengine

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
)

type kubeJobStatus struct {
	Active    int32 `json:"active"`
	Succeeded int32 `json:"succeeded"`
	Failed    int32 `json:"failed"`
}

type kubeJob struct {
	Status kubeJobStatus `json:"status"`
}

type kubePodList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

func sanitizeKubeName(name string) string {
	return sanitizeKubeNameFallback(name, "job")
}

func (e *Engine) runLabppJob(ctx context.Context, log Logger, name string, args []string, env map[string]string, taskID int) error {
	image := strings.TrimSpace(e.cfg.LabppRunnerImage)
	if image == "" {
		return fmt.Errorf("labpp runner image is not configured")
	}
	pullPolicy := strings.TrimSpace(e.cfg.LabppRunnerPullPolicy)
	if pullPolicy == "" {
		pullPolicy = "IfNotPresent"
	}
	pvcName := strings.TrimSpace(e.cfg.LabppRunnerPVCName)
	if pvcName == "" {
		pvcName = "skyforge-data"
	}

	jobName := sanitizeKubeName(name)
	ns := kubeNamespace()
	payload := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name": jobName,
			"labels": map[string]any{
				"app":              "skyforge-labpp",
				"skyforge-task-id": fmt.Sprintf("%d", time.Now().UnixNano()),
			},
		},
		"spec": map[string]any{
			"backoffLimit":            0,
			"ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						"app": "skyforge-labpp",
					},
				},
				"spec": map[string]any{
					"restartPolicy": "Never",
					"containers": []map[string]any{
						{
							"name":            "labpp",
							"image":           image,
							"imagePullPolicy": pullPolicy,
							"args":            args,
							"env":             kubeEnvList(env),
							"volumeMounts": []map[string]any{
								{
									"name":      "labpp-test",
									"mountPath": "/opt/skyforge/test",
								},
								{
									"name":      "skyforge-data",
									"mountPath": "/var/lib/skyforge",
								},
								{
									"name":      "platform-data",
									"mountPath": "/data",
								},
								{
									"name":      "eve-runner-ssh-key",
									"mountPath": "/run/secrets/eve-runner-ssh-key",
									"subPath":   "eve-runner-ssh-key",
									"readOnly":  true,
								},
							},
						},
					},
					"volumes": []map[string]any{
						{
							"name": "labpp-test",
							"emptyDir": map[string]any{
								"sizeLimit": "512Mi",
							},
						},
						{
							"name": "skyforge-data",
							"persistentVolumeClaim": map[string]any{
								"claimName": pvcName,
							},
						},
						{
							"name": "platform-data",
							"persistentVolumeClaim": map[string]any{
								"claimName": "platform-data",
							},
						},
						{
							"name": "eve-runner-ssh-key",
							"secret": map[string]any{
								"secretName": "eve-runner-ssh-key",
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
	defer kubeDeleteJob(context.Background(), ns, jobName)

	log.Infof("LabPP runner job created: %s", jobName)
	return kubeWaitJob(ctx, ns, jobName, log, func() bool {
		if taskID <= 0 || e == nil {
			return false
		}
		canceled, _ := e.taskCanceled(ctx, taskID)
		return canceled
	})
}

func kubeEnvList(env map[string]string) []map[string]any {
	if len(env) == 0 {
		return nil
	}
	items := make([]map[string]any, 0, len(env))
	for key, value := range env {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		items = append(items, map[string]any{
			"name":  key,
			"value": value,
		})
	}
	return items
}

func kubeCreateJob(ctx context.Context, ns string, payload map[string]any) error {
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs", ns)
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
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("kube job create failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeDeleteJob(ctx context.Context, ns, name string) error {
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs/%s?propagationPolicy=Background", ns, name)
	req, err := kubeRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Deleting an already-gone job is an idempotent success.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("kube job delete failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func kubeWaitJob(ctx context.Context, ns, name string, log Logger, canceled func() bool) error {
	client, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	started := time.Now()
	var lastHeartbeat time.Time
	var lastLog string
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("labpp run canceled")
		case <-ticker.C:
			if canceled != nil && canceled() {
				_ = kubeDeleteJob(context.Background(), ns, name)
				return fmt.Errorf("labpp run canceled")
			}
			status, err := kubeGetJobStatus(ctx, client, ns, name)
			if err != nil {
				log.Errorf("LabPP job status error: %v", err)
			}
			if time.Since(lastHeartbeat) >= 30*time.Second {
				lastHeartbeat = time.Now()
				log.Infof("LabPP runner still running (elapsed %s)", time.Since(started).Truncate(time.Second))
			}
			if logs, err := kubeGetJobLogs(ctx, client, ns, name); err == nil {
				if len(logs) > len(lastLog) {
					appendJobLogs(logs[len(lastLog):], log)
					lastLog = logs
				}
			}
			if status.Failed > 0 {
				if shouldIgnoreLabppFailedJob(lastLog) {
					log.Infof("LabPP job failed after success marker; treating as success")
					return nil
				}
				return fmt.Errorf("labpp job failed: %s", tailLines(lastLog, 40))
			}
			if status.Succeeded > 0 {
				return nil
			}
		}
	}
}

func shouldIgnoreLabppFailedJob(logs string) bool {
	logs = strings.TrimSpace(logs)
	if logs == "" {
		return false
	}
	for _, marker := range []string{
		"runsnapshotchecks",
		"no forward properties file found",
		"fwd init helps to create these",
	} {
		if strings.Contains(strings.ToLower(logs), marker) {
			return true
		}
	}
	return false
}

func kubeGetJobStatus(ctx context.Context, client *http.Client, ns, name string) (kubeJobStatus, error) {
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs/%s", ns, name)
	req, err := kubeRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return kubeJobStatus{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return kubeJobStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return kubeJobStatus{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return kubeJobStatus{}, fmt.Errorf("kube job status failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var job kubeJob
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return kubeJobStatus{}, err
	}
	return job.Status, nil
}

func kubeGetJobLogs(ctx context.Context, client *http.Client, ns, jobName string) (string, error) {
	podsURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods?labelSelector=%s", ns, url.QueryEscape("job-name="+jobName))
	req, err := kubeRequest(ctx, http.MethodGet, podsURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kube pods list failed: %s", resp.Status)
	}
	var pods kubePodList
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", nil
	}
	podName := strings.TrimSpace(pods.Items[0].Metadata.Name)
	if podName == "" {
		return "", nil
	}
	logURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods/%s/log?timestamps=true", ns, podName)
	logReq, err := kubeRequest(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return "", err
	}
	logResp, err := client.Do(logReq)
	if err != nil {
		return "", err
	}
	defer logResp.Body.Close()
	if logResp.StatusCode < 200 || logResp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(logResp.Body, 16<<10))
		return "", fmt.Errorf("kube log get failed: %s: %s", logResp.Status, strings.TrimSpace(string(data)))
	}
	data, _ := io.ReadAll(io.LimitReader(logResp.Body, 2<<20))
	return string(data), nil
}

func appendJobLogs(raw string, log Logger) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		log.Infof("%s", line)
	}
}

func tailLines(raw string, n int) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	lines := strings.Split(raw, "\n")
	if n <= 0 || len(lines) <= n {
		return strings.TrimSpace(raw)
	}
	return strings.TrimSpace(strings.Join(lines[len(lines)-n:], "\n"))
}
