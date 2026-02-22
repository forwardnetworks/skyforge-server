package skyforge

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TaskLifecycleEvents streams structured task lifecycle events as Server-Sent Events (SSE).
//
// The stream is backed by `sf_task_events` and supports `Last-Event-ID` replay.
//
//encore:api auth raw method=GET path=/api/runs/:id/lifecycle
func (s *Service) TaskLifecycleEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	rawID := ""
	if pv := req.PathValue("id"); pv != "" {
		rawID = pv
	} else {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		for i := 0; i+1 < len(parts); i++ {
			if parts[i] == "runs" {
				rawID = parts[i+1]
				break
			}
		}
	}
	taskID, _ := strconv.Atoi(strings.TrimSpace(rawID))
	if taskID <= 0 {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}

	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := req.Context()
	task, err := getTask(ctx, s.db, taskID)
	if err != nil || task == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _, scopeUser, err := s.loadUserScopeByKey(task.UserScopeID)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if userScopeAccessLevelForClaims(s.cfg, scopeUser, claims) == "none" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	lastID := int64(0)
	if raw := strings.TrimSpace(req.Header.Get("Last-Event-ID")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			lastID = parsed
		}
	}

	stream, err := newSSEStream(w)
	if err != nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	stream.comment("ok")
	stream.flush()

	hub := ensurePGNotifyHub(s.db)
	updates := hub.subscribe(ctx)
	reloadSignals := make(chan struct{}, 1)
	go func() {
		payloadWant := strconv.Itoa(taskID)
		for {
			select {
			case <-ctx.Done():
				return
			case n, ok := <-updates:
				if !ok {
					return
				}
				if n.Channel != pgNotifyTasksChannel {
					continue
				}
				if strings.TrimSpace(n.Payload) != payloadWant {
					continue
				}
				select {
				case reloadSignals <- struct{}{}:
				default:
				}
			}
		}
	}()

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
		rows, err := listTaskEventsAfter(ctxReq, s.db, taskID, lastID, 500)
		cancel()
		if err != nil {
			stream.comment("retry")
			stream.flush()
			continue
		}

		if len(rows) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-reloadSignals:
				continue
			case <-pingTicker.C:
				stream.comment("ping")
				stream.flush()
				continue
			}
		}

		entries := make([]TaskEventEntry, 0, len(rows))
		for _, row := range rows {
			entries = append(entries, row.Entry)
			if row.ID > lastID {
				lastID = row.ID
			}
		}
		payload, _ := json.Marshal(map[string]any{
			"cursor":  lastID,
			"entries": entries,
		})
		stream.event(lastID, "lifecycle", payload)
		stream.flush()
	}
}
