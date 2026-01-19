package kubeutil

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func InClusterConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster kube config: %w", err)
	}
	return cfg, nil
}

func ExecPodCommand(ctx context.Context, kcfg *rest.Config, ns, podName, container string, cmd []string) (stdout, stderr string, err error) {
	if kcfg == nil {
		return "", "", fmt.Errorf("kube config required")
	}
	if ns == "" || podName == "" {
		return "", "", fmt.Errorf("namespace and pod name required")
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return "", "", err
	}

	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(ns).
		SubResource("exec")
	req.VersionedParams(opts, scheme.ParameterCodec)
	execURL := req.URL()

	executor, err := remotecommand.NewSPDYExecutor(kcfg, http.MethodPost, execURL)
	if err != nil {
		return "", "", err
	}

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	streamErr := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &outBuf,
		Stderr: &errBuf,
	})
	return outBuf.String(), errBuf.String(), streamErr
}

func ExecPodShell(ctx context.Context, kcfg *rest.Config, ns, podName, container, script string) (stdout, stderr string, err error) {
	if script == "" {
		return "", "", fmt.Errorf("empty command")
	}
	cmd := []string{"sh", "-lc", script}
	return ExecPodCommand(ctx, kcfg, ns, podName, container, cmd)
}
