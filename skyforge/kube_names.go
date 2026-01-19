package skyforge

import "encore.app/internal/kubeutil"

func sanitizeKubeNameFallback(name string, fallback string) string {
	return kubeutil.SanitizeNameFallback(name, fallback)
}
