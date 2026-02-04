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
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		PodIP   string `json:"podIP"`
		Phase   string `json:"phase"`
		Reason  string `json:"reason"`
		Message string `json:"message"`

		ContainerStatuses []struct {
			Name         string `json:"name"`
			Ready        bool   `json:"ready"`
			RestartCount int    `json:"restartCount"`
			Image        string `json:"image"`
			ImageID      string `json:"imageID"`
			State        struct {
				Waiting *struct {
					Reason  string `json:"reason"`
					Message string `json:"message"`
				} `json:"waiting,omitempty"`
				Terminated *struct {
					ExitCode int    `json:"exitCode"`
					Reason   string `json:"reason"`
					Message  string `json:"message"`
				} `json:"terminated,omitempty"`
			} `json:"state,omitempty"`
			LastState struct {
				Terminated *struct {
					ExitCode int    `json:"exitCode"`
					Reason   string `json:"reason"`
					Message  string `json:"message"`
				} `json:"terminated,omitempty"`
			} `json:"lastState,omitempty"`
		} `json:"containerStatuses,omitempty"`
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

func kubeAssertClabernetesNativeMode(ctx context.Context, ns, topologyOwner string) error {
	ns = strings.TrimSpace(ns)
	topologyOwner = strings.TrimSpace(topologyOwner)
	if ns == "" || topologyOwner == "" {
		return fmt.Errorf("namespace and topology owner are required")
	}
	pods, err := kubeListPods(ctx, ns, map[string]string{"clabernetes/topologyOwner": topologyOwner})
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		return fmt.Errorf("no clabernetes pods found for topology %q", topologyOwner)
	}

	var bad []string
	for _, p := range pods {
		podName := strings.TrimSpace(p.Metadata.Name)
		node := strings.TrimSpace(p.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			// If we cannot identify the topology node, skip strict validation for this pod.
			continue
		}
		hasNodeContainer := false
		hasLauncherContainer := false
		containerNames := make([]string, 0, len(p.Status.ContainerStatuses))
		for _, cs := range p.Status.ContainerStatuses {
			name := strings.TrimSpace(cs.Name)
			if name == "" {
				continue
			}
			containerNames = append(containerNames, name)
			if name == node {
				hasNodeContainer = true
			}
			if name == "clabernetes-launcher" {
				hasLauncherContainer = true
			}
		}
		if !hasLauncherContainer || !hasNodeContainer {
			bad = append(bad, fmt.Sprintf("pod=%s node=%s containers=%v", podName, node, containerNames))
		}
	}
	if len(bad) == 0 {
		return nil
	}

	msg := "clabernetes native mode is required, but pods do not appear to be running in native mode (Docker-in-Docker likely active). " +
		"This typically indicates the clabernetes Topology CRD is missing spec.deployment.nativeMode and is pruning the field."
	if len(bad) > 5 {
		bad = bad[:5]
	}
	return fmt.Errorf("%s; examples: %s", msg, strings.Join(bad, "; "))
}

func kubeClabernetesTopologyPodsReady(ctx context.Context, ns, topologyOwner string) (bool, []string, error) {
	ns = strings.TrimSpace(ns)
	topologyOwner = strings.TrimSpace(topologyOwner)
	if ns == "" || topologyOwner == "" {
		return false, nil, fmt.Errorf("namespace and topology owner are required")
	}
	pods, err := kubeListPods(ctx, ns, map[string]string{"clabernetes/topologyOwner": topologyOwner})
	if err != nil {
		return false, nil, err
	}
	if len(pods) == 0 {
		return false, nil, nil
	}

	var notReady []string
	for _, p := range pods {
		podName := strings.TrimSpace(p.Metadata.Name)
		if podName == "" {
			podName = "<unknown>"
		}
		if strings.TrimSpace(p.Status.Phase) != "Running" {
			notReady = append(notReady, fmt.Sprintf("%s phase=%s", podName, strings.TrimSpace(p.Status.Phase)))
			continue
		}
		allContainersReady := true
		for _, cs := range p.Status.ContainerStatuses {
			if !cs.Ready {
				allContainersReady = false
				break
			}
		}
		if !allContainersReady {
			notReady = append(notReady, fmt.Sprintf("%s containersReady=false", podName))
		}
	}

	return len(notReady) == 0, notReady, nil
}

func kubeSummarizePodsForJob(ctx context.Context, ns, jobName string) (string, error) {
	pods, err := kubeListPods(ctx, ns, map[string]string{"job-name": jobName})
	if err != nil {
		return "", err
	}
	if len(pods) == 0 {
		return "", nil
	}

	var b strings.Builder
	for _, p := range pods {
		name := strings.TrimSpace(p.Metadata.Name)
		phase := strings.TrimSpace(p.Status.Phase)
		reason := strings.TrimSpace(p.Status.Reason)
		msg := strings.TrimSpace(p.Status.Message)
		node := strings.TrimSpace(p.Spec.NodeName)
		ip := strings.TrimSpace(p.Status.PodIP)

		fmt.Fprintf(&b, "pod=%s phase=%s node=%s ip=%s", name, phase, node, ip)
		if reason != "" {
			fmt.Fprintf(&b, " reason=%s", reason)
		}
		if msg != "" {
			fmt.Fprintf(&b, " message=%q", msg)
		}
		b.WriteString("\n")

		for _, cs := range p.Status.ContainerStatuses {
			cname := strings.TrimSpace(cs.Name)
			if cname == "" {
				cname = "container"
			}
			fmt.Fprintf(&b, "  container=%s ready=%t restarts=%d image=%s\n", cname, cs.Ready, cs.RestartCount, strings.TrimSpace(cs.Image))
			if cs.State.Waiting != nil {
				wr := strings.TrimSpace(cs.State.Waiting.Reason)
				wm := strings.TrimSpace(cs.State.Waiting.Message)
				if wr != "" || wm != "" {
					fmt.Fprintf(&b, "    waiting reason=%s message=%q\n", wr, wm)
				}
			}
			if cs.State.Terminated != nil {
				tr := strings.TrimSpace(cs.State.Terminated.Reason)
				tm := strings.TrimSpace(cs.State.Terminated.Message)
				fmt.Fprintf(&b, "    terminated exitCode=%d reason=%s message=%q\n", cs.State.Terminated.ExitCode, tr, tm)
			}
			if cs.LastState.Terminated != nil {
				lr := strings.TrimSpace(cs.LastState.Terminated.Reason)
				lm := strings.TrimSpace(cs.LastState.Terminated.Message)
				fmt.Fprintf(&b, "    lastTerminated exitCode=%d reason=%s message=%q\n", cs.LastState.Terminated.ExitCode, lr, lm)
			}
		}
	}
	return strings.TrimSpace(b.String()), nil
}
