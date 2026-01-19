package skyforge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	tryCloudflareURLRe = regexp.MustCompile(`https?://[a-zA-Z0-9-]+\.trycloudflare\.com`)

	cloudflaredURLCacheMu      sync.Mutex
	cloudflaredURLCacheValue   string
	cloudflaredURLCacheFetched time.Time
)

type kubePodList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

// detectCloudflaredQuickTunnelURL best-effort discovers the current trycloudflare.com URL by
// reading recent logs from the skyforge-cloudflared deployment (quick tunnel mode).
//
// This returns an empty string when cloudflared isn't running or the URL isn't found.
func detectCloudflaredQuickTunnelURL(ctx context.Context) string {
	cloudflaredURLCacheMu.Lock()
	if time.Since(cloudflaredURLCacheFetched) < 15*time.Second {
		v := cloudflaredURLCacheValue
		cloudflaredURLCacheMu.Unlock()
		return v
	}
	cloudflaredURLCacheMu.Unlock()

	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := kubeHTTPClient()
	if err != nil {
		return ""
	}

	ns := kubeNamespace()
	pod, err := kubeFindPodByLabelSelector(ctxReq, client, ns, "app.kubernetes.io/component=cloudflared")
	if err != nil || pod == "" {
		setCloudflaredCache("")
		return ""
	}

	logs, err := kubeGetPodLogsTail(ctxReq, client, ns, pod, "cloudflared", 200)
	if err != nil {
		setCloudflaredCache("")
		return ""
	}

	match := tryCloudflareURLRe.FindString(logs)
	match = strings.TrimSpace(match)
	setCloudflaredCache(match)
	return match
}

func setCloudflaredCache(v string) {
	cloudflaredURLCacheMu.Lock()
	defer cloudflaredURLCacheMu.Unlock()
	cloudflaredURLCacheValue = v
	cloudflaredURLCacheFetched = time.Now()
}

func kubeFindPodByLabelSelector(ctx context.Context, client *http.Client, ns, selector string) (string, error) {
	q := url.QueryEscape(strings.TrimSpace(selector))
	u := "https://kubernetes.default.svc/api/v1/namespaces/" + url.PathEscape(ns) + "/pods?labelSelector=" + q
	req, err := kubeRequest(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return "", nil
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

func kubeGetPodLogsTail(ctx context.Context, client *http.Client, ns, pod, container string, tail int) (string, error) {
	qs := url.Values{}
	if container != "" {
		qs.Set("container", container)
	}
	if tail > 0 {
		qs.Set("tailLines", strconv.Itoa(tail))
	}
	logURL := "https://kubernetes.default.svc/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(pod) + "/log?" + qs.Encode()
	req, err := kubeRequest(ctx, "GET", logURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return "", nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
