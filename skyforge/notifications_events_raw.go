package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// NotificationsEvents streams notifications as Server-Sent Events (SSE).
//
// This endpoint is intended to reduce portal-side polling. It streams a small
// "snapshot" payload whenever notifications change for the authenticated user.
//
// Query params:
// - include_read=true|false (default false)
// - limit=1..100 (default 50)
//
//encore:api auth raw method=GET path=/api/notifications/events
func NotificationsEvents(w http.ResponseWriter, req *http.Request) {
	if defaultService == nil || defaultService.db == nil || defaultService.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	claims, err := defaultService.sessionManager.Parse(req)
	if err != nil || claims == nil || strings.TrimSpace(claims.Username) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	username := strings.ToLower(strings.TrimSpace(claims.Username))

	q := req.URL.Query()
	includeRead := false
	if raw := strings.TrimSpace(q.Get("include_read")); raw != "" {
		includeRead = strings.EqualFold(raw, "true") || raw == "1"
	}
	limit := 50
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 100 {
			limit = v
		}
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

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
		notifications, err := listNotifications(ctxReq, defaultService.db, username, includeRead, limit)
		cancel()
		if err != nil {
			write(": retry\n\n")
			flusher.Flush()
		} else {
			payloadBytes, _ := json.Marshal(map[string]any{
				"notifications": notifications,
				"refreshedAt":   time.Now().UTC().Format(time.RFC3339),
			})
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

		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		updated := waitForNotificationUpdateSignal(waitCtx, defaultService.db, username)
		cancel()
		if updated {
			continue
		}
		write(": ping\n\n")
		flusher.Flush()
	}
}

