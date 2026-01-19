package skyforge

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
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

	stream, err := newSSEStream(w)
	if err != nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := req.Context()
	stream.comment("ok")
	stream.flush()

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
			stream.comment("retry")
			stream.flush()
		} else {
			payloadBytes, _ := json.Marshal(resp)
			payload := strings.TrimSpace(string(payloadBytes))
			if payload != "" && payload != lastPayload {
				lastPayload = payload
				lastEventID++
				stream.event(lastEventID, skyforgecore.SSEEventSnapshot, []byte(payload))
				stream.flush()
			} else {
				stream.comment("ping")
				stream.flush()
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
