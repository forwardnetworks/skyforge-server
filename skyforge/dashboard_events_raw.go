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

	"encore.app/internal/skyforgecore"
)

type dashboardSnapshot struct {
	RefreshedAt  string                 `json:"refreshedAt"`
	UserContexts []SkyforgeWorkspace    `json:"userContexts"`
	Deployments  []UserDeployment       `json:"deployments"`
	Runs         []JSONMap              `json:"runs"`
	TemplatesAt  string                 `json:"templatesIndexUpdatedAt,omitempty"`
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

func listDeploymentsForDashboard(ctx context.Context, db *sql.DB, userContextID string) ([]UserDeployment, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_workspace_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE workspace_id=$1
ORDER BY updated_at DESC`, userContextID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UserDeployment, 0, 16)
	for rows.Next() {
		var (
			rec                 UserDeployment
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
		rec.UserContextID = userContextID
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		{
			qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			summary, err := getDeploymentQueueSummary(qctx, db, userContextID, rec.ID)
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
			rec.LastTaskUserContextID = &v
		}
		if lastTaskID.Valid {
			v := int(lastTaskID.Int64)
			rec.LastTaskID = &v
		}
		if lastStatus.Valid {
			v := lastStatus.String
			rec.LastStatus = &v
		} else {
			v := "created"
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

	if _, err := svc.ensureDefaultUserContext(ctx, user); err != nil {
		log.Printf("default user context ensure: %v", err)
	}
	userContexts, err := svc.userContextStore.load()
	if err != nil {
		return nil, err
	}

	// Best-effort sync group membership like ListUserContexts does.
	changed := false
	changedUserContexts := make([]SkyforgeWorkspace, 0)
	for i := range userContexts {
		if role, ok := syncGroupMembershipForUser(&userContexts[i], claims); ok {
			changed = true
			changedUserContexts = append(changedUserContexts, userContexts[i])
			log.Printf("user-context group sync: %s -> %s (%s)", claims.Username, userContexts[i].Slug, role)
		}
	}
	if changed {
		updatedAll := true
		for _, w := range changedUserContexts {
			if err := svc.userContextStore.upsert(w); err != nil {
				updatedAll = false
				log.Printf("user-context upsert after group sync (%s): %v", w.ID, err)
			}
		}
		if updatedAll {
			for _, w := range changedUserContexts {
				syncGiteaCollaboratorsForUserContext(svc.cfg, w)
			}
		}
	}

	filtered := make([]SkyforgeWorkspace, 0, len(userContexts))
	for _, w := range userContexts {
		if userContextAccessLevelForClaims(svc.cfg, w, claims) != "none" {
			filtered = append(filtered, w)
		}
	}
	userContexts = filtered
	sort.Slice(userContexts, func(i, j int) bool { return userContexts[i].Name < userContexts[j].Name })

	deployments := make([]UserDeployment, 0, 32)
	runs := make([]JSONMap, 0, 64)
	for _, w := range userContexts {
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
					// Hide internal bootstrap tasks from the dashboard. These run as part
					// of first-login/user-context creation and are not actionable for users.
					switch strings.TrimSpace(task.TaskType) {
					case skyforgecore.TaskTypeUserBootstrap, skyforgecore.TaskTypeWorkspaceBootstrap:
						continue
					}
					run := taskToRunInfo(task)
					run["userContextId"] = w.ID
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
		return (deployments[i].UserContextID + ":" + deployments[i].ID) < (deployments[j].UserContextID + ":" + deployments[j].ID)
	})
	sort.Slice(runs, func(i, j int) bool {
		return intFromAny(runs[i]["id"]) > intFromAny(runs[j]["id"])
	})

	templatesAt := ""
	{
		qctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		var maxUpdated sql.NullTime
		err := svc.db.QueryRowContext(qctx, "SELECT max(updated_at) FROM sf_template_indexes").Scan(&maxUpdated)
		cancel()
		if err == nil && maxUpdated.Valid {
			templatesAt = maxUpdated.Time.UTC().Format(time.RFC3339)
		}
	}

	return &dashboardSnapshot{
		RefreshedAt:  time.Now().UTC().Format(time.RFC3339),
		UserContexts: userContexts,
		Deployments:  deployments,
		Runs:         runs,
		TemplatesAt:  templatesAt,
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
func (s *Service) DashboardEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

	// Subscribe to updates *before* loading data to avoid race conditions.
	// We want to trigger a reload on 'dashboard' events.
	hub := ensurePGNotifyHub(s.db)
	updates := hub.subscribe(ctx)

	// Drain pg NOTIFY events continuously so the subscription channel cannot fill
	// up while we're doing an expensive snapshot load. If the channel fills, the
	// hub drops signals and the UI can look stale until the next keep-alive.
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
				switch n.Channel {
				case pgNotifyDashboardChannel, pgNotifyTasksChannel, pgNotifyDeploymentEventsChan, pgNotifyUserContextsChannel:
					select {
					case reloadSignals <- struct{}{}:
					default:
						// Coalesce.
					}
				}
			}
		}
	}()

	lastPayload := ""
	id := int64(0)

	// Initial load
	reload := true

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		if reload {
			snap, err := loadDashboardSnapshot(ctx, s, claims)
			if err != nil {
				stream.comment("retry")
				stream.flush()
			} else {
				payloadBytes, _ := json.Marshal(snap)
				payload := strings.TrimSpace(string(payloadBytes))
				if payload == "" {
					stream.comment("retry")
					stream.flush()
				} else if payload != lastPayload {
					lastPayload = payload
					id++
					stream.event(id, skyforgecore.SSEEventSnapshot, []byte(payload))
					stream.flush()
				}
			}
			reload = false
		}

		// Wait for update or keep-alive
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
