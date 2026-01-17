package skyforge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StatusSummaryEvents streams the platform status summary as Server-Sent Events (SSE).
//
// This endpoint is public and intended to remove portal-side polling on the status page.
//
//encore:api public raw method=GET path=/status/summary/events
func (s *Service) StatusSummaryEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	write := func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, format, args...)
	}

	ctx := req.Context()
	write(": ok\n\n")
	flusher.Flush()

	lastPayload := ""
	lastEventID := int64(0)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		resp, err := s.StatusSummary(req.Context())
		if err != nil {
			write(": retry\n\n")
			flusher.Flush()
		} else {
			payloadBytes, _ := json.Marshal(resp)
			payload := strings.TrimSpace(string(payloadBytes))
			if payload != "" && payload != lastPayload {
				lastPayload = payload
				lastEventID++
				write("id: %d\n", lastEventID)
				write("event: snapshot\n")
				write("data: %s\n\n", payload)
				flusher.Flush()
			} else {
				write(": ping\n\n")
				flusher.Flush()
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
