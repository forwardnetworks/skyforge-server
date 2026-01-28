package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func listWebhookEventsForUser(ctx context.Context, db *sql.DB, username string, limit int) ([]WebhookEvent, error) {
	if db == nil {
		return []WebhookEvent{}, nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return []WebhookEvent{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `SELECT id, received_at, method, path, COALESCE(source_ip::text,''), COALESCE(body,'')
FROM sf_webhook_events
WHERE username=$1
ORDER BY id DESC
LIMIT $2`

	rows, err := db.QueryContext(ctx, query, username, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]WebhookEvent, 0, limit)
	for rows.Next() {
		var ev WebhookEvent
		var src, body string
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &ev.Method, &ev.Path, &src, &body); err != nil {
			return nil, err
		}
		ev.Method = strings.ToUpper(strings.TrimSpace(ev.Method))
		ev.Path = strings.TrimSpace(ev.Path)
		ev.SourceIP = strings.TrimSpace(src)
		ev.Body = body
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// WebhookEventsStream streams the webhook inbox as Server-Sent Events (SSE).
//
// It emits "snapshot" events (JSON payload) whenever new webhook events are ingested
// for the authenticated user.
//
// Query params:
// - limit=1..1000 (default 200)
//
//encore:api auth raw method=GET path=/api/webhooks/events/stream
func (s *Service) WebhookEventsStream(w http.ResponseWriter, req *http.Request) {
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

	limit := 200
	if raw := strings.TrimSpace(req.URL.Query().Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 1000 {
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
				if n.Channel != pgNotifyWebhooksChannel {
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
			events, err := listWebhookEventsForUser(ctx, s.db, username, limit)
			if err != nil {
				stream.comment("retry")
				stream.flush()
			} else {
				payloadBytes, _ := json.Marshal(map[string]any{
					"events":      events,
					"refreshedAt": time.Now().UTC().Format(time.RFC3339),
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
