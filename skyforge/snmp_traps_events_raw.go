package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func listSnmpTrapEventsForUser(ctx context.Context, db *sql.DB, username string, limit int) ([]SnmpTrapEvent, error) {
	if db == nil {
		return []SnmpTrapEvent{}, nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return []SnmpTrapEvent{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT id, received_at, COALESCE(source_ip::text,''), COALESCE(oid,''), COALESCE(vars_json,'')
FROM sf_snmp_trap_events
WHERE username=$1
ORDER BY id DESC
LIMIT $2
`, username, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]SnmpTrapEvent, 0, limit)
	for rows.Next() {
		var ev SnmpTrapEvent
		var src, oid, vars string
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &src, &oid, &vars); err != nil {
			return nil, err
		}
		ev.SourceIP = strings.TrimSpace(src)
		ev.OID = strings.TrimSpace(oid)
		ev.VarsJSON = vars
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SnmpTrapEventsStream streams SNMP trap inbox events as Server-Sent Events (SSE).
//
// Query params:
// - limit=1..1000 (default 200)
//
//encore:api auth raw method=GET path=/api/snmp/traps/events/stream
func (s *Service) SnmpTrapEventsStream(w http.ResponseWriter, req *http.Request) {
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

		events, err := listSnmpTrapEventsForUser(ctx, s.db, username, limit)
		if err != nil {
			write(": retry\n\n")
			flusher.Flush()
		} else {
			payloadBytes, _ := json.Marshal(map[string]any{
				"events":      events,
				"refreshedAt": time.Now().UTC().Format(time.RFC3339),
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
		updated := waitForSnmpUpdateSignal(waitCtx, s.db, username)
		cancel()
		if updated {
			continue
		}
		write(": ping\n\n")
		flusher.Flush()
	}
}
