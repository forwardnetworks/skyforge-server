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
				if n.Channel != pgNotifySyslogChannel {
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
			events, err := listSyslogEventsForUser(ctx, s.db, username, limit)
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
