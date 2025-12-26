package skyforge

import (
	"net/http"
	"strings"
	"sync"

	"encore.app/integrations/semaphore"
)

var (
	semaphoreClientMu  sync.Mutex
	semaphoreClientCfg semaphore.Config
	semaphoreClient    *semaphore.Client
)

func semaphoreClientFor(cfg Config) *semaphore.Client {
	semaphoreClientMu.Lock()
	defer semaphoreClientMu.Unlock()

	next := semaphore.Config{
		BaseURL:      cfg.SemaphoreURL,
		Token:        cfg.SemaphoreToken,
		Username:     cfg.SemaphoreUsername,
		Password:     cfg.SemaphorePassword,
		PasswordFile: cfg.SemaphorePasswordFile,
	}

	if semaphoreClient == nil || semaphoreClientCfg != next {
		semaphoreClientCfg = next
		semaphoreClient = semaphore.New(next)
	}
	return semaphoreClient
}

func semaphoreDo(cfg Config, method, path string, payload any) (*http.Response, []byte, error) {
	resp, body, err := semaphoreClientFor(cfg).Do(method, path, payload)
	if err != nil {
		return resp, body, err
	}
	if resp == nil {
		return resp, body, err
	}
	if resp.StatusCode != http.StatusNotFound && !looksLikeHTML(body) {
		return resp, body, err
	}
	altCfg, ok := alternateSemaphoreConfig(cfg)
	if !ok {
		return resp, body, err
	}
	altResp, altBody, altErr := semaphoreClientFor(altCfg).Do(method, path, payload)
	if altErr != nil {
		return resp, body, err
	}
	if altResp == nil {
		return resp, body, err
	}
	if altResp.StatusCode == http.StatusNotFound || looksLikeHTML(altBody) {
		return resp, body, err
	}
	return altResp, altBody, nil
}

func alternateSemaphoreConfig(cfg Config) (Config, bool) {
	base := cfg.SemaphoreURL
	if strings.Contains(base, "/semaphore/api") {
		cfg.SemaphoreURL = strings.Replace(base, "/semaphore/api", "/api", 1)
		return cfg, true
	}
	if strings.HasSuffix(base, "/api") {
		cfg.SemaphoreURL = strings.TrimSuffix(base, "/api") + "/semaphore/api"
		return cfg, true
	}
	return cfg, false
}

func looksLikeHTML(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "<!DOCTYPE html>") || strings.HasPrefix(trimmed, "<html")
}
