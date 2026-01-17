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

func listSyslogEventsForUser(ctx context.Context, db *sql.DB, username string, limit int) ([]SyslogEvent, error) {
	if db == nil {
		return []SyslogEvent{}, nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return []SyslogEvent{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `
SELECT
  e.id,
  e.received_at,
  e.source_ip::text,
  COALESCE(e.hostname, ''),
  COALESCE(e.app_name, ''),
  e.facility,
  e.severity,
  COALESCE(e.message, ''),
  COALESCE(r.owner_username, ''),
  COALESCE(r.source_cidr::text, '')
FROM sf_syslog_events e
LEFT JOIN LATERAL (
  SELECT owner_username, source_cidr
  FROM sf_syslog_routes
  WHERE e.source_ip <<= source_cidr
  ORDER BY masklen(source_cidr) DESC
  LIMIT 1
) r ON TRUE
WHERE r.owner_username = $1
ORDER BY e.id DESC
LIMIT $2
`

	rows, err := db.QueryContext(ctx, query, username, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]SyslogEvent, 0, limit)
	for rows.Next() {
		var ev SyslogEvent
		var facility sql.NullInt64
		var severity sql.NullInt64
		var hostname, appName, message, owner, cidr string
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &ev.SourceIP, &hostname, &appName, &facility, &severity, &message, &owner, &cidr); err != nil {
			return nil, err
		}
		ev.Hostname = strings.TrimSpace(hostname)
		ev.AppName = strings.TrimSpace(appName)
		ev.Message = strings.TrimSpace(message)
		if facility.Valid {
			v := int(facility.Int64)
			ev.Facility = &v
		}
		if severity.Valid {
			v := int(severity.Int64)
			ev.Severity = &v
		}
		owner = strings.TrimSpace(owner)
		cidr = strings.TrimSpace(cidr)
		if owner != "" {
			ev.Owner = owner
		}
		if cidr != "" {
			ev.RouteCIDR = cidr
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SyslogEventsStream streams syslog inbox events as Server-Sent Events (SSE).
//
// Query params:
// - limit=1..1000 (default 200)
//
//encore:api auth raw method=GET path=/api/syslog/events/stream
func (s *Service) SyslogEventsStream(w http.ResponseWriter, req *http.Request) {
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

		events, err := listSyslogEventsForUser(ctx, s.db, username, limit)
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
		updated := waitForSyslogUpdateSignal(waitCtx, s.db, username)
		cancel()
		if updated {
			continue
		}
		write(": ping\n\n")
		flusher.Flush()
	}
}
