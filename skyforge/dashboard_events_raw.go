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
	Contexts     []SkyforgeUserContext  `json:"contexts"`
	Scopes       []SkyforgeUserContext  `json:"-"` // legacy internal field
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

func listDeploymentsForDashboard(ctx context.Context, db *sql.DB, ownerID string) ([]UserDeployment, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_owner_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE owner_username=$1
ORDER BY updated_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UserDeployment, 0, 16)
	for rows.Next() {
		var (
			rec             UserDeployment
			raw             json.RawMessage
			lastTaskOwnerID sql.NullInt64
			lastTaskID      sql.NullInt64
			lastStatus      sql.NullString
			lastStarted     sql.NullTime
			lastFinished    sql.NullTime
			createdAt       time.Time
			updatedAt       time.Time
		)
		if err := rows.Scan(
			&rec.ID,
			&rec.Name,
			&rec.Type,
			&raw,
			&rec.CreatedBy,
			&createdAt,
			&updatedAt,
			&lastTaskOwnerID,
			&lastTaskID,
			&lastStatus,
			&lastStarted,
			&lastFinished,
		); err != nil {
			return nil, err
		}
		rec.OwnerUsername = ownerID
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		{
			qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			summary, err := getDeploymentQueueSummary(qctx, db, ownerID, rec.ID)
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
		if lastTaskOwnerID.Valid {
			v := int(lastTaskOwnerID.Int64)
			rec.LastTaskOwnerID = &v
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

	if _, err := svc.ensureDefaultOwnerContext(ctx, user); err != nil {
		log.Printf("default scope ensure: %v", err)
	}
	scopes, err := svc.scopeStore.load()
	if err != nil {
		return nil, err
	}

	// Best-effort sync group membership like GetUsers does.
	changed := false
	changedScopes := make([]SkyforgeUserContext, 0)
	for i := range scopes {
		if role, ok := syncGroupMembershipForUser(&scopes[i], claims); ok {
			changed = true
			changedScopes = append(changedScopes, scopes[i])
			log.Printf("context group sync: %s -> %s (%s)", claims.Username, scopes[i].Slug, role)
		}
	}
	if changed {
		updatedAll := true
		for _, w := range changedScopes {
			if err := svc.scopeStore.upsert(w); err != nil {
				updatedAll = false
				log.Printf("context upsert after group sync (%s): %v", w.ID, err)
			}
		}
		if updatedAll {
			for _, w := range changedScopes {
				syncGiteaCollaboratorsForScope(svc.cfg, w)
			}
		}
	}

	filtered := make([]SkyforgeUserContext, 0, len(scopes))
	for _, w := range scopes {
		if ownerAccessLevelForClaims(svc.cfg, w, claims) != "none" {
			filtered = append(filtered, w)
		}
	}
	scopes = filtered
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })

	deployments := make([]UserDeployment, 0, 32)
	runs := make([]JSONMap, 0, 64)
	for _, w := range scopes {
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
					// of first-login/context creation and are not actionable for users.
					switch strings.TrimSpace(task.TaskType) {
					case skyforgecore.TaskTypeUserBootstrap, skyforgecore.TaskTypeContextBootstrap:
						continue
					}
					run := taskToRunInfo(task)
					run["ownerUsername"] = w.ID
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
		return (deployments[i].OwnerUsername + ":" + deployments[i].ID) < (deployments[j].OwnerUsername + ":" + deployments[j].ID)
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
		Contexts:     scopes,
		Scopes:       scopes,
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
				case pgNotifyDashboardChannel, pgNotifyTasksChannel, pgNotifyDeploymentEventsChan, pgNotifyUsersChannel:
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
