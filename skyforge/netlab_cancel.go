package skyforge

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (s *Service) cancelNetlabJob(ctx context.Context, apiURL, jobID string, insecure bool, auth netlabAPIAuth, log *taskLogger) {
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	jobID = strings.TrimSpace(jobID)
	if apiURL == "" || jobID == "" {
		return
	}
	if log == nil {
		log = &taskLogger{svc: s, taskID: 0}
	}
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, body, err := netlabAPIDo(ctxReq, fmt.Sprintf("%s/jobs/%s/cancel", apiURL, jobID), map[string]any{}, insecure, auth)
	if err != nil {
		log.Errorf("Netlab cancel request failed: %v", err)
		return
	}
	if resp == nil {
		log.Errorf("Netlab cancel request failed: no response")
		return
	}
	if resp.StatusCode == http.StatusNotFound {
		log.Infof("Netlab cancel: job not found (treated as canceled).")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Errorf("Netlab cancel rejected: %s", strings.TrimSpace(string(body)))
		return
	}
	log.Infof("Netlab cancel requested for job %s", jobID)
}
