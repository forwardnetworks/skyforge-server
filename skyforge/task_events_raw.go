package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

// TaskLifecycleEvents streams structured task lifecycle events as Server-Sent Events (SSE).
//
// The stream is backed by `sf_task_events` and supports `Last-Event-ID` replay.
//
//encore:api auth raw method=GET path=/api/runs/:id/lifecycle
func TaskLifecycleEvents(w http.ResponseWriter, req *http.Request) {
	if defaultService == nil || defaultService.db == nil || defaultService.sessionManager == nil {
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

	claims, err := defaultService.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := req.Context()
	task, err := getTask(ctx, defaultService.db, taskID)
	if err != nil || task == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _, workspace, err := defaultService.loadWorkspaceByKey(task.WorkspaceID)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if workspaceAccessLevelForClaims(defaultService.cfg, workspace, claims) == "none" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	lastID := int64(0)
	if raw := strings.TrimSpace(req.Header.Get("Last-Event-ID")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			lastID = parsed
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

	write(": ok\n\n")
	flusher.Flush()

	var sub *redis.PubSub
	var updates <-chan *redis.Message
	if redisClient != nil {
		sub = redisClient.Subscribe(ctx, taskUpdateChannel(taskID))
		defer func() { _ = sub.Close() }()
		ctxSub, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, _ = sub.Receive(ctxSub)
		cancel()
		updates = sub.Channel()
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
			rows, err := listTaskEventsAfter(ctxReq, defaultService.db, taskID, lastID, 500)
			cancel()
			if err != nil {
				write(": retry\n\n")
				flusher.Flush()
				continue
			}
			if len(rows) == 0 {
				if updates != nil {
					select {
					case <-ctx.Done():
						return
					case <-updates:
						continue
					case <-time.After(30 * time.Second):
						write(": ping\n\n")
						flusher.Flush()
						continue
					}
				}
				time.Sleep(2 * time.Second)
				write(": ping\n\n")
				flusher.Flush()
				continue
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
			write("id: %d\n", lastID)
			write("event: lifecycle\n")
			write("data: %s\n\n", strings.TrimSpace(string(payload)))
			flusher.Flush()
		}
	}
}
