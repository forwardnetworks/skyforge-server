package skyforge

import (
	"context"

	"encore.app/internal/kubeutil"
)

func kubeEnsureNamespace(ctx context.Context, ns string) error {
	return kubeutil.EnsureNamespace(ctx, ns)
}

func kubeUpsertConfigMap(ctx context.Context, ns, name string, data map[string]string, labels map[string]string) error {
	return kubeutil.UpsertConfigMap(ctx, ns, name, data, labels)
}

func kubeDeleteConfigMap(ctx context.Context, ns, name string) (bool, error) {
	return kubeutil.DeleteConfigMap(ctx, ns, name)
}

func kubeDeleteConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	return kubeutil.DeleteConfigMapsByLabel(ctx, ns, selector)
}

func kubeCountConfigMapsByLabel(ctx context.Context, ns string, selector map[string]string) (int, error) {
	return kubeutil.CountConfigMapsByLabel(ctx, ns, selector)
}

func kubeCreateClabernetesTopology(ctx context.Context, ns string, payload map[string]any) error {
	return kubeutil.CreateClabernetesTopology(ctx, ns, payload)
}

func kubeDeleteClabernetesTopology(ctx context.Context, ns, name string) (bool, error) {
	return kubeutil.DeleteClabernetesTopology(ctx, ns, name)
}

type kubeClabernetesTopology = kubeutil.ClabernetesTopology

func kubeGetClabernetesTopology(ctx context.Context, ns, name string) (*kubeClabernetesTopology, int, error) {
	return kubeutil.GetClabernetesTopology(ctx, ns, name)
}
