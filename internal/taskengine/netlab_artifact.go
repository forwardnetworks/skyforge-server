package taskengine

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

func netlabAPIGetJobArtifact(ctx context.Context, apiURL, jobID, filePath string, insecure bool, auth netlabAPIAuth) ([]byte, error) {
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	jobID = strings.TrimSpace(jobID)
	filePath = strings.TrimSpace(filePath)
	if apiURL == "" || jobID == "" || filePath == "" {
		return nil, fmt.Errorf("netlab artifact request missing apiURL/jobID/path")
	}
	q := url.Values{}
	q.Set("path", filePath)
	endpoint := fmt.Sprintf("%s/jobs/%s/artifact?%s", apiURL, url.PathEscape(jobID), q.Encode())
	resp, body, err := netlabAPIGet(ctx, endpoint, insecure, auth)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("netlab artifact fetch failed: %s", strings.TrimSpace(string(body)))
	}
	return body, nil
}
