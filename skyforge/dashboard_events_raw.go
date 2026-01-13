package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type dashboardSnapshot struct {
	RefreshedAt  string                 `json:"refreshedAt"`
	Workspaces   []SkyforgeWorkspace    `json:"workspaces"`
	Deployments  []WorkspaceDeployment  `json:"deployments"`
	Runs         []JSONMap              `json:"runs"`
	AwsSsoStatus *dashboardAwsSsoStatus `json:"awsSsoStatus,omitempty"`
}

type dashboardAwsSsoStatus struct {
	Configured          bool   `json:"configured"`
	Connected           bool   `json:"connected"`
	ExpiresAt           string `json:"expiresAt,omitempty"`
	LastAuthenticatedAt string `json:"lastAuthenticatedAt,omitempty"`
}

func buildDashboardAwsSsoStatus(cfg Config, store awsSSOTokenStore, username string) *dashboardAwsSsoStatus {
	if store == nil {
		return nil
	}
	record, err := store.get(username)
	if err != nil {
		return nil
	}
	status := &dashboardAwsSsoStatus{
		Configured: cfg.AwsSSOStartURL != "" && cfg.AwsSSORegion != "",
		Connected:  record != nil && strings.TrimSpace(record.RefreshToken) != "",
	}
	if record != nil && !record.AccessTokenExpiresAt.IsZero() {
		status.ExpiresAt = record.AccessTokenExpiresAt.UTC().Format(time.RFC3339)
	}
	if record != nil && !record.LastAuthenticatedAtUTC.IsZero() {
		status.LastAuthenticatedAt = record.LastAuthenticatedAtUTC.UTC().Format(time.RFC3339)
	}
	return status
}

func listDeploymentsForDashboard(ctx context.Context, db *sql.DB, workspaceID string) ([]WorkspaceDeployment, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_workspace_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE workspace_id=$1
ORDER BY updated_at DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]WorkspaceDeployment, 0, 16)
	for rows.Next() {
		var (
			rec                 WorkspaceDeployment
			raw                 json.RawMessage
			lastTaskWorkspaceID sql.NullInt64
			lastTaskID          sql.NullInt64
			lastStatus          sql.NullString
			lastStarted         sql.NullTime
			lastFinished        sql.NullTime
			createdAt           time.Time
			updatedAt           time.Time
		)
		if err := rows.Scan(
			&rec.ID,
			&rec.Name,
			&rec.Type,
			&raw,
			&rec.CreatedBy,
			&createdAt,
			&updatedAt,
			&lastTaskWorkspaceID,
			&lastTaskID,
			&lastStatus,
			&lastStarted,
			&lastFinished,
		); err != nil {
			return nil, err
		}
		rec.WorkspaceID = workspaceID
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		{
			qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			summary, err := getDeploymentQueueSummary(qctx, db, workspaceID, rec.ID)
			cancel()
			if err == nil && summary != nil {
				if summary.ActiveTaskID > 0 {
					rec.ActiveTaskID = &summary.ActiveTaskID
				}
				if strings.TrimSpace(summary.ActiveTaskStatus) != "" {
					status := strings.TrimSpace(summary.ActiveTaskStatus)
					rec.ActiveTaskStatus = &status
				}
				rec.QueueDepth = &summary.QueueDepth
			}
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &rec.Config); err != nil {
				rec.Config = JSONMap{}
			}
		} else {
			rec.Config = JSONMap{}
		}
		if lastTaskWorkspaceID.Valid {
			v := int(lastTaskWorkspaceID.Int64)
			rec.LastTaskWorkspaceID = &v
		}
		if lastTaskID.Valid {
			v := int(lastTaskID.Int64)
			rec.LastTaskID = &v
		}
		if lastStatus.Valid {
			v := lastStatus.String
			rec.LastStatus = &v
		}
		if lastStarted.Valid {
			v := lastStarted.Time.UTC().Format(time.RFC3339)
			rec.LastStartedAt = &v
		}
		if lastFinished.Valid {
			v := lastFinished.Time.UTC().Format(time.RFC3339)
			rec.LastFinishedAt = &v
		}
		out = append(out, rec)
	}
	return out, nil
}

func loadDashboardSnapshot(ctx context.Context, svc *Service, claims *SessionClaims) (*dashboardSnapshot, error) {
	if svc == nil || svc.db == nil {
		return nil, fmt.Errorf("service unavailable")
	}
	if claims == nil || strings.TrimSpace(claims.Username) == "" {
		return nil, fmt.Errorf("unauthorized")
	}
	user := &AuthUser{
		Username:    claims.Username,
		DisplayName: claims.DisplayName,
		Email:       claims.Email,
		Groups:      claims.Groups,
		IsAdmin:     isAdminForClaims(svc.cfg, claims),
	}

	if _, err := svc.ensureDefaultWorkspace(ctx, user); err != nil {
		log.Printf("default workspace ensure: %v", err)
	}
	workspaces, err := svc.workspaceStore.load()
	if err != nil {
		return nil, err
	}

	// Best-effort sync group membership like GetWorkspaces does.
	changed := false
	changedWorkspaces := make([]SkyforgeWorkspace, 0)
	for i := range workspaces {
		if role, ok := syncGroupMembershipForUser(&workspaces[i], claims); ok {
			changed = true
			changedWorkspaces = append(changedWorkspaces, workspaces[i])
			log.Printf("workspace group sync: %s -> %s (%s)", claims.Username, workspaces[i].Slug, role)
		}
	}
	if changed {
		if err := svc.workspaceStore.save(workspaces); err != nil {
			log.Printf("workspaces save after group sync: %v", err)
		} else {
			for _, w := range changedWorkspaces {
				syncGiteaCollaboratorsForWorkspace(svc.cfg, w)
			}
		}
	}

	filtered := make([]SkyforgeWorkspace, 0, len(workspaces))
	for _, w := range workspaces {
		if workspaceAccessLevelForClaims(svc.cfg, w, claims) != "none" {
			filtered = append(filtered, w)
		}
	}
	workspaces = filtered
	sort.Slice(workspaces, func(i, j int) bool { return workspaces[i].Name < workspaces[j].Name })

	deployments := make([]WorkspaceDeployment, 0, 32)
	runs := make([]JSONMap, 0, 64)
	for _, w := range workspaces {
		{
			rows, err := listDeploymentsForDashboard(ctx, svc.db, w.ID)
			if err == nil {
				deployments = append(deployments, rows...)
			}
		}
		{
			qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			tasks, err := listTasks(qctx, svc.db, w.ID, 50)
			cancel()
			if err == nil {
				runItems := make([]map[string]any, 0, len(tasks))
				for _, task := range tasks {
					run := taskToRunInfo(task)
					run["workspaceId"] = w.ID
					runItems = append(runItems, run)
				}
				items, err := toJSONMapSlice(runItems)
				if err == nil {
					runs = append(runs, items...)
				}
			}
		}
	}
	sort.Slice(deployments, func(i, j int) bool {
		return (deployments[i].WorkspaceID + ":" + deployments[i].ID) < (deployments[j].WorkspaceID + ":" + deployments[j].ID)
	})
	sort.Slice(runs, func(i, j int) bool {
		return intFromAny(runs[i]["id"]) > intFromAny(runs[j]["id"])
	})

	return &dashboardSnapshot{
		RefreshedAt:  time.Now().UTC().Format(time.RFC3339),
		Workspaces:   workspaces,
		Deployments:  deployments,
		Runs:         runs,
		AwsSsoStatus: buildDashboardAwsSsoStatus(svc.cfg, svc.awsStore, claims.Username),
	}, nil
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return int(n)
		}
	}
	return 0
}

// DashboardEvents streams a dashboard snapshot as Server-Sent Events (SSE).
//
//encore:api auth raw method=GET path=/api/dashboard/events
func DashboardEvents(w http.ResponseWriter, req *http.Request) {
	if defaultService == nil || defaultService.db == nil || defaultService.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, err := defaultService.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
	id := int64(0)

	var sub *redis.PubSub
	var updates <-chan *redis.Message
	if redisClient != nil {
		sub = redisClient.Subscribe(ctx, dashboardUpdateChannel())
		defer func() { _ = sub.Close() }()
		ctxSub, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, _ = sub.Receive(ctxSub)
		cancel()
		updates = sub.Channel()
	}

	for {
		snap, err := loadDashboardSnapshot(ctx, defaultService, claims)
		if err != nil {
			write(": retry\n\n")
			flusher.Flush()
		} else {
			payloadBytes, _ := json.Marshal(snap)
			payload := strings.TrimSpace(string(payloadBytes))
			if payload == "" {
				write(": retry\n\n")
				flusher.Flush()
			} else if payload != lastPayload {
				lastPayload = payload
				id++
				write("id: %d\n", id)
				write("event: snapshot\n")
				write("data: %s\n\n", payload)
				flusher.Flush()
			} else {
				write(": ping\n\n")
				flusher.Flush()
			}
		}

		// Block until a dashboard update arrives (or periodically send keep-alives).
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

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			continue
		}
	}
}
