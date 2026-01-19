package taskengine

import (
	"context"
	"io"
	"net/http"

	"encore.app/internal/kubeutil"
)

func kubeNamespace() string {
	return kubeutil.Namespace()
}

func kubeHTTPClient() (*http.Client, error) {
	return kubeutil.HTTPClient()
}

func kubeToken() (string, error) {
	return kubeutil.Token()
}

func kubeRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	return kubeutil.Request(ctx, method, url, body)
}
