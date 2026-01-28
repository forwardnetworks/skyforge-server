package skyforge

import (
	"context"
	"encoding/json"
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
func (s *Service) NotificationsEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	claims, err := s.sessionManager.Parse(req)
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

	stream, err := newSSEStream(w)
	if err != nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := req.Context()
	stream.comment("ok")
	stream.flush()

	hub := ensurePGNotifyHub(s.db)
	updates := hub.subscribe(ctx)

	reloadSignals := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case n, ok := <-updates:
				if !ok {
					return
				}
				if n.Channel != pgNotifyNotificationsChannel {
					continue
				}
				if strings.TrimSpace(n.Payload) == username {
					select {
					case reloadSignals <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	lastPayload := ""
	id := int64(0)
	reload := true

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		if reload {
			ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
			notifications, err := listNotifications(ctxReq, s.db, username, includeRead, limit)
			cancel()
			if err != nil {
				stream.comment("retry")
				stream.flush()
			} else {
				payloadBytes, _ := json.Marshal(map[string]any{
					"notifications": notifications,
					"refreshedAt":   time.Now().UTC().Format(time.RFC3339),
				})
				payload := strings.TrimSpace(string(payloadBytes))
				if payload != "" && payload != lastPayload {
					lastPayload = payload
					id++
					stream.event(id, "snapshot", []byte(payload))
					stream.flush()
				}
			}
			reload = false
		}

		select {
		case <-ctx.Done():
			return
		case <-reloadSignals:
			reload = true
		case <-pingTicker.C:
			stream.comment("ping")
			stream.flush()
		}
	}
}
