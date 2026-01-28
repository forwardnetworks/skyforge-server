package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

func loadWorkspacesSnapshot(ctx context.Context, svc *Service, claims *SessionClaims, all bool) ([]SkyforgeWorkspace, error) {
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
		updatedAll := true
		for _, w := range changedWorkspaces {
			if err := svc.workspaceStore.upsert(w); err != nil {
				updatedAll = false
				log.Printf("workspaces upsert after group sync (%s): %v", w.ID, err)
			}
		}
		if updatedAll {
			for _, w := range changedWorkspaces {
				syncGiteaCollaboratorsForWorkspace(svc.cfg, w)
			}
			if svc.db != nil {
				_ = notifyWorkspacesUpdatePG(ctx, svc.db, "*")
				_ = notifyDashboardUpdatePG(ctx, svc.db)
			}
		}
	}

	if !all {
		filtered := make([]SkyforgeWorkspace, 0, len(workspaces))
		for _, w := range workspaces {
			if workspaceAccessLevelForClaims(svc.cfg, w, claims) != "none" {
				filtered = append(filtered, w)
			}
		}
		workspaces = filtered
	}
	sort.Slice(workspaces, func(i, j int) bool { return workspaces[i].Name < workspaces[j].Name })

	return workspaces, nil
}

// WorkspacesEvents streams the workspace list as Server-Sent Events (SSE).
//
// Query params:
// - all=true (admin only; default false)
//
//encore:api auth raw method=GET path=/api/workspaces-events
func (s *Service) WorkspacesEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil || strings.TrimSpace(claims.Username) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	all := strings.EqualFold(strings.TrimSpace(req.URL.Query().Get("all")), "true")
	if all && !isAdminForClaims(s.cfg, claims) {
		http.Error(w, "forbidden", http.StatusForbidden)
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

	// Subscribe to updates before the initial snapshot load to avoid race windows
	// where we miss a pg NOTIFY and look stale until the keep-alive.
	hub := ensurePGNotifyHub(s.db)
	updates := hub.subscribe(ctx)

	// Drain pg NOTIFY continuously to avoid the hub dropping signals while we
	// perform snapshot loads.
	reloadSignals := make(chan struct{}, 1)
	claimUser := strings.ToLower(strings.TrimSpace(claims.Username))
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case n, ok := <-updates:
				if !ok {
					return
				}
				if n.Channel != pgNotifyWorkspacesChannel {
					continue
				}
				payload := strings.ToLower(strings.TrimSpace(n.Payload))
				if payload == "*" || payload == claimUser {
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
	reload := true

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		if reload {
			workspaces, err := loadWorkspacesSnapshot(ctx, s, claims, all)
			if err != nil {
				stream.comment("retry")
				stream.flush()
			} else {
				payloadBytes, _ := json.Marshal(map[string]any{
					"user":        claims.Username,
					"workspaces":  workspaces,
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
