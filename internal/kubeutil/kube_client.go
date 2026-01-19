package kubeutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Namespace() string {
	if ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); ns != "" {
		return ns
	}
	return "skyforge"
}

func HTTPClient() (*http.Client, error) {
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caBytes, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, fmt.Errorf("read kube ca: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caBytes); !ok {
		return nil, fmt.Errorf("parse kube ca")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

func Token() (string, error) {
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	b, err := os.ReadFile(filepath.Clean(tokenPath))
	if err != nil {
		return "", fmt.Errorf("read kube token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("empty kube token")
	}
	return tok, nil
}

func Request(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	token, err := Token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return req, nil
}
