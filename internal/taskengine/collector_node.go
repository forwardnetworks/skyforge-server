package taskengine

import (
	"context"
	"strings"
)

// best-effort: find the Kubernetes node hosting the user's in-cluster Forward collector.
// Used to co-locate lab pods with the collector when cross-node pod routing is flaky.
func kubeCollectorNodeForUser(ctx context.Context, username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", nil
	}
	pods, err := kubeListPods(ctx, kubeNamespace(), map[string]string{
		"app.kubernetes.io/component": "collector",
		"skyforge-username":           username,
	})
	if err != nil {
		return "", err
	}
	for _, pod := range pods {
		if strings.EqualFold(strings.TrimSpace(pod.Status.Phase), "Running") && strings.TrimSpace(pod.Spec.NodeName) != "" {
			return strings.TrimSpace(pod.Spec.NodeName), nil
		}
	}
	for _, pod := range pods {
		if strings.TrimSpace(pod.Spec.NodeName) != "" {
			return strings.TrimSpace(pod.Spec.NodeName), nil
		}
	}
	return "", nil
}

