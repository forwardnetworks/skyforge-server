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

func (s *Service) runLabppJob(ctx context.Context, log *taskLogger, name string, args []string, env map[string]string) error {
	image := strings.TrimSpace(s.cfg.LabppRunnerImage)
	if image == "" {
		return fmt.Errorf("labpp runner image is not configured")
	}
	pullPolicy := strings.TrimSpace(s.cfg.LabppRunnerPullPolicy)
	if pullPolicy == "" {
		pullPolicy = "IfNotPresent"
	}
	pvcName := strings.TrimSpace(s.cfg.LabppRunnerPVCName)
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
	return kubeWaitJob(ctx, ns, jobName, log)
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

func kubeDeleteJob(ctx context.Context, ns, name string) {
	client, err := kubeHTTPClient()
	if err != nil {
		return
	}
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/batch/v1/namespaces/%s/jobs/%s?propagationPolicy=Background", ns, name)
	req, err := kubeRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func kubeWaitJob(ctx context.Context, ns, name string, log *taskLogger) error {
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
				return fmt.Errorf("labpp job failed")
			}
			if status.Succeeded > 0 {
				return nil
			}
		}
	}
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
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return kubeJobStatus{}, fmt.Errorf("kube job get failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var job kubeJob
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return kubeJobStatus{}, err
	}
	return job.Status, nil
}

func kubeGetJobLogs(ctx context.Context, client *http.Client, ns, name string) (string, error) {
	podName, err := kubeFindJobPod(ctx, client, ns, name)
	if err != nil {
		return "", err
	}
	if podName == "" {
		return "", nil
	}
	logURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods/%s/log?container=labpp&timestamps=true", ns, podName)
	req, err := kubeRequest(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return "", fmt.Errorf("kube job logs failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func kubeFindJobPod(ctx context.Context, client *http.Client, ns, name string) (string, error) {
	selector := url.QueryEscape("job-name=" + name)
	url := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods?labelSelector=%s", ns, selector)
	req, err := kubeRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return "", fmt.Errorf("kube job pods failed: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var pods kubePodList
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", nil
	}
	return pods.Items[0].Metadata.Name, nil
}

func appendJobLogs(raw string, log *taskLogger) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		log.Infof("%s", line)
	}
}

func sanitizeKubeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	if name == "" {
		return "labpp-job"
	}
	if len(name) > 63 {
		name = name[:63]
	}
	name = strings.Trim(name, "-")
	if name == "" {
		return "labpp-job"
	}
	return name
}
